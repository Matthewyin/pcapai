import { Agent, OpenAIProvider, Runner, tool, withTrace, type Tool } from "@openai/agents";
import { z } from "zod";
import { AgentIntentEnum, AnalysisChainPlanSchema, type AgentAnswer, type AnalysisChainPlan, type AnalysisChainStep, type CaseGraph } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";
import { getTsharkQueryMcp, resetTsharkQueryMcp } from "../mcp/tsharkQueryMcpRuntime.js";

type RuntimeInput = {
  graph: CaseGraph;
  question: string;
  chatHistory?: Array<{ role: "user" | "assistant"; content: string }>;
  onTrace?: (message: string) => void;
  tools?: Tool[];
};

export const AgentIntentSchema = z.object({
  intent: z.enum([
    "usage_help",
    "protocol_statistics",
    "network_statistics",
    "tcp_session_query",
    "protocol_event_query",
    "capture_correlation",
    "mapping_hint_update",
    "active_query_explain",
    "selected_session_diagnosis",
    "report_request",
    "needs_clarification",
    "llm_explain"
  ]),
  confidence: z.enum(["high", "medium", "low"]),
  reason: z.string().default(""),
  missingContext: z.array(z.string()).default([])
});
export type AgentIntentPlan = z.infer<typeof AgentIntentSchema>;

type CompatibilityInput = {
  apiKey: string;
  baseURL: string;
  model: string;
  providerData: Record<string, unknown>;
};

const jsonOutputInstruction = [
  "最终只能输出一个 JSON 对象，不要使用 Markdown。",
  "禁止把 <think> 思考内容当作最终输出；思考结束后必须继续调用工具或直接输出最终 JSON。",
  "JSON 字段固定为 answer、evidenceIds、packetIds、sessionLinkIds、findingIds、missingContext、confidence、suggestedActions、suggestedQueries、handoffAgent。",
  "suggestedQueries 是一个数组，每项包含 question（可执行的问题文本）、reason（为什么建议这个查询）、intent（推荐 intent）。",
  "如果调用过 suggest_next_query，把返回的建议放入 suggestedQueries。",
  "没有内容的数组填 []，没有 confidence 或 handoffAgent 时填 null。"
].join("\n");

function stringArrayFrom(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean);
  if (typeof value === "string") return value.trim() ? [value.trim()] : [];
  return [];
}

function confidenceFrom(value: unknown): AgentAnswer["confidence"] {
  if (value === "certain" || value === "high" || value === "low" || value === "needs_context") return value;
  if (typeof value === "number") {
    if (value >= 0.85) return "high";
    if (value >= 0.5) return "low";
    return "needs_context";
  }
  return undefined;
}

function formatAgentAnswer(answer: AgentAnswer): AgentAnswer {
  return { ...answer, answer: answer.answer.trim() || "当前没有形成可解释的结论。" };
}

function normalizeSuggestedQueries(value: unknown): Array<{ question: string; reason: string; intent: string }> {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Record<string, unknown> => item && typeof item === "object" && typeof item.question === "string").map((item) => ({
    question: String(item.question),
    reason: typeof item.reason === "string" ? item.reason : "",
    intent: typeof item.intent === "string" ? item.intent : "llm_explain"
  }));
}

function diagnosticPhaseFrom(value: unknown): AgentAnswer["diagnosticPhase"] {
  if (value === "interview" || value === "hypothesis" || value === "testing" || value === "conclusion") return value;
  return undefined;
}

function normalizeHypotheses(value: unknown): Array<{ id: string; description: string; status: "pending" | "testing" | "confirmed" | "ruled_out"; evidenceFor: string[]; evidenceAgainst: string[] }> {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Record<string, unknown> => item && typeof item === "object" && typeof item.id === "string" && typeof item.description === "string").map((item) => ({
    id: String(item.id),
    description: String(item.description),
    status: item.status === "pending" || item.status === "testing" || item.status === "confirmed" || item.status === "ruled_out" ? item.status : "pending",
    evidenceFor: stringArrayFrom(item.evidenceFor),
    evidenceAgainst: stringArrayFrom(item.evidenceAgainst)
  }));
}

function normalizeAgentObject(value: Record<string, unknown>): AgentAnswer {
  const answer = {
    answer: typeof value.answer === "string" ? value.answer : JSON.stringify(value),
    evidenceIds: stringArrayFrom(value.evidenceIds),
    packetIds: stringArrayFrom(value.packetIds),
    sessionLinkIds: stringArrayFrom(value.sessionLinkIds),
    findingIds: stringArrayFrom(value.findingIds),
    missingContext: stringArrayFrom(value.missingContext),
    confidence: confidenceFrom(value.confidence),
    suggestedActions: stringArrayFrom(value.suggestedActions),
    suggestedQueries: normalizeSuggestedQueries(value.suggestedQueries),
    handoffAgent: typeof value.handoffAgent === "string" && value.handoffAgent.trim() ? value.handoffAgent : undefined,
    followUpQuestions: stringArrayFrom(value.followUpQuestions).length ? stringArrayFrom(value.followUpQuestions) : undefined,
    diagnosticPhase: diagnosticPhaseFrom(value.diagnosticPhase),
    hypotheses: normalizeHypotheses(value.hypotheses).length ? normalizeHypotheses(value.hypotheses) : undefined
  };
  return formatAgentAnswer(answer);
}

function parseAgentOutput(output: unknown): AgentAnswer {
  const rawText = typeof output === "string" ? output : JSON.stringify(output);
  // 部分模型会把 <think> 推理块留在最终消息里，剥离后再解析，避免内部推理泄漏给用户；
  // 剥离后为空则交给 formatAgentAnswer 落到默认结论文案
  const text = rawText.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  const jsonText = firstJsonObject(text);
  if (jsonText) {
    try {
      const parsed = JSON.parse(jsonText);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return normalizeAgentObject(parsed as Record<string, unknown>);
    } catch {
      // Fall through to plain text. The LLM boundary is allowed to be messy.
    }
  }
  return formatAgentAnswer({
    answer: text,
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: [],
    suggestedActions: [],
    suggestedQueries: []
  });
}

function firstJsonObject(text: string) {
  const start = text.indexOf("{");
  if (start < 0) return "";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const char = text[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === "\"") {
        inString = false;
      }
      continue;
    }
    if (char === "\"") {
      inString = true;
    } else if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, index + 1);
    }
  }
  return "";
}

function parseChainPlanOutput(output: unknown, question: string): AnalysisChainPlan {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const jsonText = firstJsonObject(text);
  if (!jsonText) throw new Error(`chain planner returned non-json output: ${text.slice(0, 500)}`);
  const parsed = JSON.parse(jsonText);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`chain planner returned non-object: ${text.slice(0, 500)}`);
  }
  const value = parsed as Record<string, unknown>;
  let confidence = typeof value.confidence === "string" ? value.confidence.trim().toLowerCase() : "medium";
  if (confidence === "certain" || confidence === "confident" || confidence === "确定") confidence = "high";
  if (confidence === "needs_context" || confidence === "uncertain" || confidence === "不确定") confidence = "low";
  if (confidence !== "high" && confidence !== "medium" && confidence !== "low") confidence = "medium";
  value.confidence = confidence;
  if (typeof value.missingContext === "string") value.missingContext = value.missingContext.trim() ? [value.missingContext] : [];
  if (value.missingContext === null || value.missingContext === undefined) value.missingContext = [];
  if (!value.chainId) value.chainId = `chain-${Date.now()}`;
  if (!value.question) value.question = question;
  if (!value.planKind) value.planKind = value.steps && Array.isArray(value.steps) && value.steps.length > 1 ? "chain" : "single";
  if (!value.reason) value.reason = "";
  const steps = Array.isArray(value.steps) ? value.steps : [];
  const validIntents = new Set(AgentIntentEnum.options);
  const validatedSteps: Array<{ stepId: string; intent: string; purpose: string; params?: unknown; paramsFrom?: unknown }> = steps.filter((step: unknown): step is Record<string, unknown> => {
    if (!step || typeof step !== "object" || Array.isArray(step)) return false;
    const s = step as Record<string, unknown>;
    return typeof s.intent === "string" && validIntents.has(s.intent as z.infer<typeof AgentIntentEnum>);
  }).map((step: Record<string, unknown>, index: number) => ({
    stepId: typeof step.stepId === "string" ? step.stepId : `step-${index}`,
    intent: step.intent as string,
    purpose: typeof step.purpose === "string" ? step.purpose : String(step.intent),
    params: step.params || undefined,
    paramsFrom: step.paramsFrom || undefined
  }));
  if (!validatedSteps.length) {
    value.planKind = "single";
    value.steps = [{ stepId: "step-0", intent: "llm_explain", purpose: "默认 LLM 解释" }];
  } else {
    value.steps = validatedSteps;
  }
  return AnalysisChainPlanSchema.parse(value);
}

type ChatMessage = { role: string; content: string };

function intentPlannerContext(graph: CaseGraph, question: string, chatHistory?: ChatMessage[]) {
  const activeQueryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns[0];
  return {
    question,
    caseId: graph.spec.caseId,
    captureCount: graph.captures.length,
    captures: graph.captures.map((capture) => ({
      nodeId: capture.nodeId,
      name: capture.name,
      role: capture.role,
      direction: capture.interfaceDirection,
      pcapFilename: capture.pcapFilename,
      packetCount: capture.packetCount
    })),
    activeQueryRun: activeQueryRun ? {
      queryRunId: activeQueryRun.queryRunId,
      question: activeQueryRun.question,
      protocol: activeQueryRun.protocol,
      displayFilter: activeQueryRun.displayFilter,
      selectedConversationId: activeQueryRun.selectedConversationId,
      evidenceCardCount: activeQueryRun.evidenceCards.length,
      hasPath: Boolean(activeQueryRun.path),
      hasDiagnosis: Boolean(activeQueryRun.selectedDiagnosis)
    } : null,
    queryRunSummaries: graph.queryRuns.slice(-5).map((qr) => ({
      queryRunId: qr.queryRunId,
      question: qr.question,
      protocol: qr.protocol,
      evidenceCardCount: qr.evidenceCards?.length || 0
    })),
    chatHistory: chatHistory?.slice(-6).map((m) => ({
      role: m.role,
      content: m.content.slice(0, 200)
    })) || [],
    memory: {
      topology: graph.memory?.topology || "",
      findings: graph.memory?.findings?.slice(-10) || [],
      userNotes: graph.memory?.userNotes || []
    },
    mappingHintCount: graph.mappingHints.length,
    timeOffsetHintCount: graph.timeOffsetHints.length
  };
}

function modelSettingsFrom(providerData: Record<string, unknown>) {
  return Object.keys(providerData).length ? { providerData } : {};
}

// 每次运行入口快照 LLM 配置并构造局部 Runner，避免请求间通过全局 provider 互相覆盖
function snapshotLlmRunner() {
  const llm = { ...apiConfig.llm, providerData: { ...apiConfig.llm.providerData } };
  const runner = new Runner({
    modelProvider: new OpenAIProvider({
      apiKey: llm.apiKey,
      baseURL: llm.baseURL,
      useResponses: llm.useResponses
    })
  });
  return { llm, runner };
}

type ChainPlannerInput = {
  graph: CaseGraph;
  question: string;
  chatHistory?: ChatMessage[];
  onTrace?: (message: string) => void;
};

export async function runChainPlanner(input: ChainPlannerInput): Promise<AnalysisChainPlan> {
  const { llm, runner } = snapshotLlmRunner();
  input.onTrace?.(`Chain Planner 使用模型：${llm.model}，端点：${llm.baseURL}`);

  const chainPlannerAgent = new Agent({
    name: "PcapChainPlanner",
    instructions: [
      "你是 pcapAI 的分析链规划器，根据用户问题和当前 case graph 规划分析步骤。",
      "你必须输出一个 JSON 对象，不要 Markdown，不要解释。",
      "字段固定为 plan_kind、steps、confidence、reason、missingContext。",
      "",
      "plan_kind 规则：",
      "- 如果一个 intent 就能回答，输出 \"single\"，steps 只有 1 步。",
      "- 如果需要多步推理（先查 A，用 A 的结果再查 B），输出 \"chain\"，steps 包含 2-5 步。",
      "",
      "steps 中每个 step 的字段：stepId（\"step-0\", \"step-1\"...）、intent、purpose（中文描述这一步要做什么）、params（可选的结构化查询参数对象）。",
      "如果某个 step 的查询参数来自前序 step 的结果，用 paramsFrom 字段表达。",
      "paramsFrom 的 key 是查询参数名（srcIp, dstIp, port, protocol），value 是路径表达式如 \"step-0.dstIp\"。",
      "每个 step 执行后会暴露结构化结果：TCP 会话查询暴露 srcIp/dstIp/srcPort/dstPort/port，DNS 查询暴露解析出的地址（dstIp 和 resolvedIps）。",
      "",
      "intent 只能是以下之一：",
      "- usage_help：用户问怎么使用、帮助、流程。",
      "- protocol_statistics：协议种类、数量、分布。",
      "- network_statistics：IP/端口/RST/重传/状态码等事实统计。",
      "- tcp_session_query：分析访问、TCP session、路径候选。",
      "- protocol_event_query：列出 DNS/HTTP/TLS/ICMP/UDP/RST/重传/Zero Window 事件。每个 step 的 purpose 应只涉及一种协议或一种事件类型，不要在同一个 step 同时查询多种协议。如需查询多种协议，拆成多个 step。该 intent 的 step 必须输出 params，至少包含 protocol 字段（tcp|dns|tls|http|icmp|udp）；protocol 为 tcp 时再加 eventKind 字段（rst|retransmission|zero_window|syn_no_synack|one_way|overview），用于确定性路由，不依赖 purpose 文本。",
      "- capture_correlation：多节点/多文件关联。",
      "- mapping_hint_update：补充 NAT/F5/LB/代理/地址转换/时间偏移。",
      "- selected_session_diagnosis：当前 session 诊断。",
      "- active_query_explain：当前查询/证据/路径解释。",
      "- report_request：生成报告、总结。",
      "- needs_clarification：缺少关键条件。",
      "- llm_explain：需要自然语言解释。",
      "",
      "不要硬编码特定故障场景。根据 case graph 的实际数据决定步骤。",
      "如果不确定，输出 plan_kind=single，intent=needs_clarification。",
      "",
      "重要：当用户问题是开放性分析问题（如\"分析异常\"、\"有什么问题\"、\"帮我看看\"），但没有故障时间、源、目的、端口、节点位置或明确协议时，必须输出 single + needs_clarification，先追问，不执行宽查询。",
      "只有用户已经给出可验证范围，或当前已有可用 QueryRun/选中 session 时，才先安排确定性步骤收集证据，最后一步用 llm_explain 综合解读证据并给出诊断结论。",
      "llm_explain 步骤的 purpose 应描述为\"综合解读前序步骤的证据，给出诊断结论和建议\"。",
      "纯统计问题（如\"协议分布\"、\"端口排名\"）不需要 llm_explain。"
    ].join("\n"),
    model: llm.model,
    modelSettings: modelSettingsFrom(llm.providerData)
  });
  input.onTrace?.("Chain Planner 正在规划分析步骤。");
  const result = await runner.run(chainPlannerAgent, JSON.stringify(intentPlannerContext(input.graph, input.question, input.chatHistory)), { maxTurns: 2 });
  const plan = parseChainPlanOutput(result.finalOutput, input.question);
  const stepSummary = plan.steps.map((step: AnalysisChainStep) => `${step.intent}(${step.purpose})`).join(" → ");
  input.onTrace?.(`Chain Planner 输出：${plan.planKind}（${plan.confidence}）${stepSummary}`);
  return plan;
}

export async function runAgentCompatibilityCheck(input: CompatibilityInput) {
  const runner = new Runner({
    modelProvider: new OpenAIProvider({
      apiKey: input.apiKey,
      baseURL: input.baseURL,
      useResponses: false
    })
  });

  let toolCalled = false;
  const compatibilityTool = tool({
    name: "compatibility_probe",
    description: "返回 Agent 兼容性测试的固定探针结果。",
    parameters: z.object({}),
    execute: () => {
      toolCalled = true;
      return "agent_compatibility_probe_ok";
    }
  });
  const settings = modelSettingsFrom(input.providerData);
  const workerAgent = new Agent({
    name: "CompatibilityWorkerAgent",
    instructions: "必须先调用 compatibility_probe，再用中文回复兼容测试通过。",
    model: input.model,
    modelSettings: settings,
    tools: [compatibilityTool]
  });
  const leaderAgent = new Agent({
    name: "CompatibilityLeaderAgent",
    instructions: "必须把用户请求交接给 CompatibilityWorkerAgent 处理。",
    handoffs: [workerAgent],
    model: input.model,
    modelSettings: settings
  });

  const result = await runner.run(leaderAgent, "执行 Agent 兼容性测试。", { maxTurns: 4 });
  if (!toolCalled) throw new Error("模型没有完成工具调用，Agent 兼容性测试未通过。");
  return { ok: true, output: String(result.finalOutput || "").slice(0, 500) };
}

export type AgentAnswerWithToolCalls = AgentAnswer & { toolCalls?: string[] };

// 诊断知识库：按 insight 类型组织，运行时只注入当前 case 实际检测到的部分
const insightDescriptions: Record<string, string> = {
  connection_lifecycle: "SYN 无 SYN/ACK、握手后 RST、半关闭",
  ack_gap: "ACK 缺失 → 重传 → RST/hung（含指数退避检测）",
  tcp_timing: "RTT 估算、空闲间隔、突发模式",
  tcp_window_trend: "接收窗口缩小、Zero Window Probe",
  tcp_rst_direction: "RST 来源方向分析（中间设备检测）、RST 风暴",
  tcp_handshake_retry: "SYN/SYNACK 重传、同时打开/关闭",
  tcp_delayed_ack: "Delayed ACK 模式统计",
  tcp_connection_flood: "SYN 突发、半开连接聚集",
  tcp_segment_anomaly: "小包/超大段异常",
  tcp_keepalive: "Keep-Alive 探测、超时断开",
  tcp_throughput: "吞吐量估算、重传开销、BDP",
  tcp_options: "SACK 协商、Timestamps、TCP Fast Open",
  http_status_chain: "3xx 重定向链、4xx/5xx 聚合、错误突发、重复 URI",
  http_header_anomaly: "Cookie 缺失/不一致、XFF 多跳、Content-Length 截断、缓存缺失、认证失败、压缩缺失、Host vs SNI 不一致",
  http_timing: "慢响应（>3s）、响应延迟聚合",
  http_uri_anomaly: "URI 大小写差异、URL 编码差异、尾部斜杠差异",
  tls_handshake: "Alert 告警、握手失败原因、TLS 版本降级、弱加密套件、证书 SAN 不匹配、ALPN 协商",
  icmp_echo_pair: "Echo/Reply 精确配对、RTT、丢包率、抖动",
  icmp_unreachable: "Unreachable 子类型分析、突发检测、与 TCP 流关联、Traceroute 模式",
  icmp_mtu: "Path MTU Discovery 黑洞检测、Fragmentation Needed 事件",
  icmp_redirect: "Redirect 消息检测、路由异常",
  dns_anomaly: "NXDOMAIN、SERVFAIL、无响应、慢解析、查询突发、TTL 异常、CNAME 链",
  udp_anomaly: "UDP 端口扫描、UDP Flood、单向上行流、QUIC 检测",
  udp_flow: "UDP 端点对聚合、流量分布",
  quic_anomaly: "QUIC 连接概览、握手状态、版本不匹配",
  ntp_anomaly: "Stratum 分布、Root Delay、时间源质量",
  ssh_anomaly: "消息类型分布、连接断开、认证失败重试",
  cross_protocol_chain: "DNS→TCP→TLS→HTTP 全链路时序分解",
  l7_proxy_detected: "Via/XFF/SSL 卸载/TCP 分段代理检测",
  nat_heuristic: "NAT 多目标/ISN/孤儿 SYN 启发式检测",
  tcp_connection_split: "TCP 连接被中间设备拆分"
};

// rfcRefs 是规范锚点：知识卡只指路不作证，结论引用必须经 get_rfc_section 回读原文
const hypothesisPlaybook: Array<{ hypothesis: string; prediction: string; insightTypes: string[]; fallbackTool: string; rfcRefs: string[] }> = [
  { hypothesis: "服务端瓶颈", prediction: "Zero Window、慢响应、无响应", insightTypes: ["ack_gap", "http_timing", "tcp_window_trend"], fallbackTool: "list_tcp_zero_window + list_http_packets", rfcRefs: ["RFC 9293（window management / zero-window probing）"] },
  { hypothesis: "网络丢包", prediction: "重传、RTT 波动", insightTypes: ["ack_gap", "tcp_timing", "icmp_echo_pair", "tcp_throughput"], fallbackTool: "list_tcp_retransmissions", rfcRefs: ["RFC 6298（RTO 计算）", "RFC 9293（retransmission）"] },
  { hypothesis: "中间设备 RST", prediction: "来自非端点的 RST", insightTypes: ["tcp_rst_direction", "connection_lifecycle"], fallbackTool: "list_tcp_resets（分析方向）", rfcRefs: ["RFC 9293（reset generation / reset processing）"] },
  { hypothesis: "SSL/TLS 问题", prediction: "Alert、握手失败、弱加密", insightTypes: ["tls_handshake", "cross_protocol_chain"], fallbackTool: "list_tls_packets", rfcRefs: ["RFC 8446（TLS 1.3 alert protocol）", "RFC 5246（TLS 1.2，已被 8446 取代）"] },
  { hypothesis: "证书问题", prediction: "SAN 不匹配、证书过期", insightTypes: ["tls_handshake"], fallbackTool: "list_tls_packets", rfcRefs: ["RFC 5280（证书与 SAN 校验）"] },
  { hypothesis: "DNS 问题", prediction: "NXDOMAIN、SERVFAIL、无响应", insightTypes: ["dns_anomaly"], fallbackTool: "list_dns_packets", rfcRefs: ["RFC 1035（rcode 语义）", "RFC 8914（Extended DNS Errors）", "RFC 2308（负缓存）"] },
  { hypothesis: "应用层慢", prediction: "HTTP 响应延迟", insightTypes: ["http_timing", "cross_protocol_chain"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 9110（HTTP 语义）"] },
  { hypothesis: "连接挂起", prediction: "ACK 缺失、重传后 RST", insightTypes: ["ack_gap", "tcp_keepalive"], fallbackTool: "query_packets", rfcRefs: ["RFC 1122（TCP keep-alive §4.2.3.6）", "RFC 9293"] },
  { hypothesis: "重定向异常", prediction: "3xx 循环、多次重定向", insightTypes: ["http_status_chain"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 9110（3xx redirection）"] },
  { hypothesis: "认证失败", prediction: "401/403、Cookie 缺失", insightTypes: ["http_header_anomaly"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 9110（401/403 语义）", "RFC 6265（Cookie）"] },
  { hypothesis: "路径匹配失败", prediction: "URI 变体、大小写/编码差异", insightTypes: ["http_uri_anomaly", "http_status_chain"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 3986（URI 规范化与等价性）"] },
  { hypothesis: "性能问题", prediction: "高延迟、低吞吐", insightTypes: ["tcp_throughput", "tcp_delayed_ack", "tcp_timing"], fallbackTool: "get_network_statistics", rfcRefs: ["RFC 7323（window scale / timestamps）", "RFC 5681（拥塞控制）"] },
  { hypothesis: "SYN Flood", prediction: "大量 SYN 无响应", insightTypes: ["tcp_connection_flood"], fallbackTool: "query_packets(SYN)", rfcRefs: ["RFC 4987（SYN Flood 缓解）"] },
  { hypothesis: "连接超时", prediction: "Keep-Alive 失败、空闲断开", insightTypes: ["tcp_keepalive", "tcp_window_trend"], fallbackTool: "query_packets", rfcRefs: ["RFC 1122（keep-alive §4.2.3.6）"] },
  { hypothesis: "压缩/缓存问题", prediction: "未压缩大响应、无缓存头", insightTypes: ["http_header_anomaly"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 9110（content coding）", "RFC 9111（HTTP 缓存）"] },
  { hypothesis: "UDP 端口扫描", prediction: "大量不同目标端口的 UDP 包", insightTypes: ["udp_anomaly"], fallbackTool: "list_udp_packets", rfcRefs: ["RFC 768（UDP）"] },
  { hypothesis: "UDP Flood", prediction: "单端口高频 UDP 突发", insightTypes: ["udp_anomaly"], fallbackTool: "list_udp_packets", rfcRefs: ["RFC 768（UDP）", "RFC 2827（BCP 38 源地址过滤）"] },
  { hypothesis: "QUIC 连接异常", prediction: "QUIC 版本不匹配、连接失败、Initial 无 Handshake 响应", insightTypes: ["udp_anomaly", "quic_anomaly"], fallbackTool: "list_udp_packets", rfcRefs: ["RFC 9000（QUIC 传输）"] },
  { hypothesis: "ICMP/PMTU 黑洞", prediction: "Fragmentation Needed 被丢弃 + TCP 重传", insightTypes: ["icmp_mtu", "icmp_unreachable", "ack_gap"], fallbackTool: "list_icmp_events", rfcRefs: ["RFC 1191（PMTUD）", "RFC 4821（PLPMTUD）", "RFC 792（ICMP）"] },
  { hypothesis: "Traceroute 问题", prediction: "TTL Exceeded 不完整、路径不对称", insightTypes: ["icmp_unreachable"], fallbackTool: "list_icmp_events", rfcRefs: ["RFC 792（TTL exceeded）"] },
  { hypothesis: "DNS 攻击/劫持/隧道", prediction: "查询突发、同域名多服务器不同结果、异常域名模式", insightTypes: ["dns_anomaly"], fallbackTool: "list_dns_packets", rfcRefs: ["RFC 5358（开放解析器风险）", "RFC 7873（DNS Cookies）"] },
  { hypothesis: "时间同步问题", prediction: "NTP Stratum 高、延迟大", insightTypes: ["ntp_anomaly"], fallbackTool: "get_expert_info", rfcRefs: ["RFC 5905（NTPv4）"] },
  { hypothesis: "SSH 连接异常", prediction: "认证重试、断开消息", insightTypes: ["ssh_anomaly"], fallbackTool: "get_expert_info", rfcRefs: ["RFC 4253（SSH 传输层）", "RFC 4252（SSH 认证）"] },
  { hypothesis: "L7 代理/SSL 卸载", prediction: "Via/XFF 头、前后端连接拆分", insightTypes: ["l7_proxy_detected", "tcp_connection_split"], fallbackTool: "list_http_packets", rfcRefs: ["RFC 9110（Via 头）", "RFC 7239（Forwarded / XFF）"] },
  { hypothesis: "NAT 转换", prediction: "多目标映射、ISN 关联、孤儿 SYN", insightTypes: ["nat_heuristic"], fallbackTool: "query_packets", rfcRefs: ["RFC 2663（NAT 术语）", "RFC 4787（NAT UDP 行为）"] }
];

// 只注入当前 case 实际检测到的洞察类型与相关假设，控制提示词体积
function hypothesisKnowledge(graph: CaseGraph) {
  // 洞察基于异常包预提取，必须如实声明覆盖范围，避免 Agent 把"洞察里没有"当成"包里没有"
  const coverageLines = graph.insightCoverage
    ? ["", "## 洞察覆盖范围（重要）", graph.insightCoverage.note, "洞察未覆盖的协议或事件不代表不存在，需用 tshark-query 工具直接验证。"]
    : ["", "注意：洞察仅基于异常包预提取，未覆盖的协议事件需用 tshark-query 工具直接验证。"];
  const counts = new Map<string, number>();
  for (const insight of graph.insights) counts.set(insight.type, (counts.get(insight.type) || 0) + 1);
  if (!counts.size) {
    return [
      "## 数据包洞察",
      "本 case 暂无自动洞察结果；先调用 get_insights 确认，再用 tshark-query 工具直接查询证据。",
      ...coverageLines
    ].join("\n");
  }
  const insightLines = [...counts.entries()].map(([type, count]) => `- ${type}（${count} 条）：${insightDescriptions[type] || "见 get_insights 明细"}`);
  const rows = hypothesisPlaybook.filter((row) => row.insightTypes.some((type) => counts.has(type)));
  const tableLines = rows.length
    ? [
      "| 假设 | 预测在包数据中看到 | 优先检查 insight 类型 | 备用查询工具 | 规范锚点（用 search_rfc/get_rfc_section 回读原文） |",
      ...rows.map((row) => `| ${row.hypothesis} | ${row.prediction} | ${row.insightTypes.join(", ")} | ${row.fallbackTool} | ${row.rfcRefs.join("；")} |`)
    ]
    : ["当前洞察类型没有匹配的预置假设；根据症状自行形成假设，用 get_insights 和 tshark-query 验证。"];
  return [
    "## 本 case 已检测到的数据包洞察（调用 get_insights 取明细，不要重复查询已有结论）",
    ...insightLines,
    ...coverageLines,
    "",
    "## 与本 case 相关的假设与预测",
    ...tableLines
  ].join("\n");
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractToolCalls(result: any): string[] {
  const tools: string[] = [];
  if (!result?.newItems) return tools;
  for (const item of result.newItems) {
    if (item.type === "tool_call_item" || item.type === "function_call") {
      const name = item.rawItem?.name;
      if (name) tools.push(name);
    }
  }
  return tools;
}

export async function runPcapTroubleshootingAgent(input: RuntimeInput): Promise<AgentAnswerWithToolCalls> {
  const { llm, runner } = snapshotLlmRunner();
  input.onTrace?.(`Agent 使用模型：${llm.model}，端点：${llm.baseURL}`);

  input.onTrace?.("正在获取常驻 tshark-query MCP 连接。");
  const tsharkQueryMcp = await getTsharkQueryMcp();
  input.onTrace?.("tshark-query MCP 已就绪；case graph 工具以进程内方式提供。");

  const mcpServers = [tsharkQueryMcp];
  const localTools = input.tools || [];
  const agentToolInstruction = localTools.length
    ? [
      "## pcapAI 本地工具",
      "你可以优先调用 pcapai_ 前缀的本地工具来创建 QueryRun、查询统计、关联多文件、诊断选中 session 或导出报告。",
      "这些工具会写入 QueryRun、EvidenceCard、checks 和 ToolRun，适合回答用户的具体排障问题。",
      "tshark-query MCP 仍用于更底层的包级查询；不要绕过 pcapai_ 工具重复做已经封装好的确定性查询。"
    ].join("\n")
    : "";

  const evidenceAgent = new Agent({
    name: "HypothesisAgent",
    instructions: [
      "你是 pcapAI 的假设验证专家。你接收诊断假设，用包数据验证或排除每个假设。",
      "",
      "## 假设验证流程",
      "",
      "1. 调用 load_case_graph 了解 case 上下文",
      "2. 调用 get_network_topology 了解网络拓扑和抓包位置",
      "3. 调用 get_insights 获取自动检测的数据包洞察结果（连接生命周期、ACK 缺失、TCP 时序、HTTP 状态链、ICMP 配对、跨协议链路等）",
      "4. 对每个假设：",
      "   - 先检查 insights 中是否已有直接相关证据",
      "   - 如果 insights 不足以验证，再调用 tshark-query MCP 查询具体证据",
      "   - 对比证据与预测，标记 status 为 confirmed 或 ruled_out",
      "   - 把支持证据写入 evidenceFor，矛盾证据写入 evidenceAgainst",
      "",
      hypothesisKnowledge(input.graph),
      "",
      "## 可用的 tshark-query 工具",
      "- list_tcp_resets / list_tcp_retransmissions / list_tcp_zero_window：TCP 异常",
      "- list_dns_packets / list_tls_packets / list_http_packets / list_icmp_events / list_udp_packets：协议事件",
      "- get_expert_info：tshark 专家分析（重传、乱序、重复 ACK、零窗口、丢失段等）",
      "- query_packets / build_display_filter：通用查询",
      "- get_network_statistics：网络统计",
      "capturesJson 参数从 case graph 的 captures 字段获取。",
      "",
      "## RFC 规范知识库",
      "- search_rfc：按英文关键词检索本地 RFC 全文（如 \"TCP zero window probe\"）；get_rfc_section：精读指定 RFC 章节原文。",
      "- 假设表中的规范锚点先用 get_rfc_section 直接精读；没有锚点时用 search_rfc 定位。",
      "- 结论中的规范依据必须经 get_rfc_section 回读原文，引用带 RFC 编号和 §section，不凭记忆引用；命中已废弃文档时改引取代它的新 RFC。",
      "",
      "## 输出格式",
      "- hypotheses 数组：每个假设的 id、description、status、evidenceFor、evidenceAgainst",
      "- answer：总结验证结果，给出因果链（症状 → 证据 → 根因）",
      "- diagnosticPhase 为 \"conclusion\"",
      "- evidenceCards：关键证据卡片",
      "",
      "## 规则",
      "- 不翻译 tshark 输出。要解释证据与假设的关系。",
      "- 拓扑信息帮助你判断异常包的来源（客户端侧 vs 服务端侧 vs 中间设备）。",
      "- 没有证据支持的假设标记为 ruled_out，不要当成结论。",
      "- 优先使用 insights 中的已有分析结果，减少不必要的 tshark 查询。",
      "- 调用 suggest_next_query 获取后续查询建议，放入 suggestedQueries。",
      jsonOutputInstruction
    ].join("\n"),
    model: llm.model,
    modelSettings: modelSettingsFrom(llm.providerData),
    mcpServers,
    tools: localTools
  });

  const pathAgent = new Agent({
    name: "PathAgent",
    instructions: [
      "你是 pcapAI 的多节点路径还原专家，具备网络拓扑感知能力。",
      "必须先调用 load_case_graph，再调用 get_network_topology 了解网络设备。",
      "然后调用 get_path_diagnosis 和 get_query_diagnosis。",
      "解释路径时结合拓扑信息：哪一跳经过了防火墙、LB、WAF 等设备，这些设备可能如何影响协议行为。",
      "解释完路径后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "只解释 PathHop、PathEdge、correlation、edge diagnosis、timeDeltaSeconds、mapping/time offset 依据。",
      "用户询问断点、哪一跳、路径、链路、上游下游、NAT/F5/LB/代理映射时，优先使用 get_path_diagnosis。",
      "如果 path edge 是 needs_context，要明确说需要补充映射、时间偏移、抓包方向或节点顺序；不能说成确定设备故障。",
      "回答必须绑定 QueryRun、PathHop/PathEdge、packetIds、findingIds 或 sessionLinkIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    model: llm.model,
    modelSettings: modelSettingsFrom(llm.providerData),
    mcpServers,
    tools: localTools
  });

  const protocolAgent = new Agent({
    name: "ProtocolAgent",
    instructions: [
      "你是 pcapAI 的协议专项诊断专家，具备网络拓扑感知和假设验证能力。",
      "必须先调用 load_case_graph，再调用 get_case_memory 了解已有的拓扑和分析结论，避免重复分析。",
      "然后调用 get_network_topology 了解网络设备和抓包位置。",
      "然后调用 get_active_query_run、get_protocol_correlations、get_evidence_cards 和 get_query_diagnosis。",
      "当需要查询原始协议数据（如 TCP RST、重传、Zero Window、DNS、TLS、HTTP、ICMP、UDP 包）时，直接调用 tshark-query MCP 的工具。调用时 capturesJson 参数从 case graph 的 captures 字段获取（JSON 字符串化的 [{nodeId, pcapFilename}] 数组）。",
      "可用的 tshark-query 工具包括：list_tcp_resets、list_tcp_retransmissions、list_tcp_zero_window、list_dns_packets、list_tls_packets、list_http_packets、list_icmp_events、list_udp_packets、query_packets、build_display_filter、get_network_statistics。",
      "需要协议规范依据时：先用 search_rfc（英文关键词）定位条文，再用 get_rfc_section 精读原文；结论引用必须带 RFC 编号和 §section，不凭记忆引用 RFC。",
      "解释完协议关联后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "用户询问 DNS、TLS、SSL、SNI、HTTP、Host、URI、状态码、ICMP、UDP 或 L7 与 TCP 的关系时，优先使用 protocolCorrelations。",
      "只解释 DNS-to-TCP、TLS-SNI-to-TCP、HTTP-Host-to-TCP 的确定性关联，不自动推断 SSL 卸载、Cookie 会话保持或后端连接池。",
      "结合拓扑信息分析协议行为：如果中间有 SSL 卸载设备，客户端侧会看到 TLS，服务端侧会看到明文 HTTP。",
      "如果缺少 protocolCorrelations，要说明当前 QueryRun 没有生成 L7-to-TCP 关联，并建议补充协议查询或过滤条件。",
      "回答必须引用 QueryRun、protocolCorrelation、evidenceCards 或 packetIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    model: llm.model,
    modelSettings: modelSettingsFrom(llm.providerData),
    mcpServers,
    tools: localTools
  });

  const memoryInstruction = [
    input.graph.memory?.topology ? `## 已确认的网络拓扑\n${input.graph.memory.topology}\n` : "",
    input.graph.memory?.findings?.length ? `## 已有分析结论\n${input.graph.memory.findings.map((f) => `- ${f.query}：${f.conclusion}`).join("\n")}\n` : "",
    input.graph.memory?.userNotes?.length ? `## 用户补充信息\n${input.graph.memory.userNotes.join("\n")}\n` : ""
  ].filter(Boolean).join("\n");

  const leaderAgent = new Agent({
    name: "PcapTroubleshootingLeaderAgent",
    instructions: [
      "你是 pcapAI 的网络排障诊断 leader。你的工作不是翻译 tshark 输出，而是像高级网络工程师一样诊断故障。",
      "",
      memoryInstruction,
      agentToolInstruction,
      "",
      "## 诊断流程",
      "",
      "根据对话上下文判断当前处于哪个诊断阶段：",
      "",
      "### 阶段 1：信息收集（interview）",
      "症状或拓扑信息不足时不要交接，由你直接收集：先调用 get_case_memory 和 load_case_graph 了解已有信息，避免重复询问；然后用 followUpQuestions 追问（每轮最多 2-3 个问题）：",
      "- 故障现象（超时、断连、慢、错误、间歇性）、受影响的服务/IP/端口、时间范围、影响范围",
      "- 网络路径经过哪些设备（防火墙、LB、WAF、SSL、代理、NAT）及其关键配置",
      "- 每个 pcap 文件的抓包位置（客户端侧/服务端侧/设备前后）和方向",
      "用户提供拓扑用 update_network_topology 保存；其他关键补充信息用 update_case_memory 保存。",
      "diagnosticPhase 为 \"interview\"。",
      "",
      "### 阶段 2：假设驱动分析（hypothesis + testing）",
      "信息充分或用户表达\"没有了\"\"就这些\"时，交给 HypothesisAgent 进行假设驱动分析：",
      "- 基于症状 + 拓扑形成 2-4 个假设",
      "- 每个假设预测在包数据中会看到什么",
      "- 用 tshark-query MCP 查询证据",
      "- 确认或排除假设",
      "diagnosticPhase 为 \"hypothesis\" 或 \"testing\"。",
      "",
      "### 阶段 3：结论（conclusion）",
      "diagnosticPhase 为 \"conclusion\"。给出因果链和针对性建议。",
      "",
      "## 专家选择规则",
      "- 假设验证、因果链分析、统计类问题 → HypothesisAgent",
      "- 多节点路径、断点分析 → PathAgent",
      "- DNS/TLS/HTTP/ICMP/UDP 协议专项 → ProtocolAgent",
      "- 生成报告 → 不交接，调用 export_report 工具获取草稿后按用户要求整理",
      "",
      "## 关键规则",
      "- 不要翻译 tshark 输出。要解释证据与故障的关系。",
      "- 不允许编造包、节点或结论。没有证据支持的假设不要当成结论。",
      "- 协议行为合规性判断优先用 search_rfc 取得条文依据，引用必须经 get_rfc_section 回读原文并带 RFC 编号与 §section，不凭记忆引用 RFC。",
      "- 当信息不足时，返回 followUpQuestions，不要猜测。",
      "- 输出必须绑定 QueryRun、evidenceIds、packetIds 等可回溯 ID。",
      jsonOutputInstruction
    ].join("\n"),
    handoffs: [evidenceAgent, pathAgent, protocolAgent],
    model: llm.model,
    modelSettings: modelSettingsFrom(llm.providerData),
    mcpServers,
    tools: localTools
  });
  input.onTrace?.(`已创建 Leader Agent 和 3 个专家 Agent，模型=${llm.model}。`);

  // 有 onTrace 时走 stream 模式，把工具调用与专家切换事件实时透传；最终 JSON 答案仍在完成后解析
  async function runLeaderAgent(contextMessage: string) {
    if (!input.onTrace) return runner.run(leaderAgent, contextMessage, { maxTurns: llm.maxTurns });
    const streamed = await runner.run(leaderAgent, contextMessage, { maxTurns: llm.maxTurns, stream: true });
    for await (const event of streamed) {
      if (event.type === "run_item_stream_event") {
        const item = event.item as { type?: string; rawItem?: { name?: string } };
        if (item.type === "tool_call_item" && item.rawItem?.name) input.onTrace(`正在调用工具：${item.rawItem.name}`);
        else if (item.type === "handoff_call_item") input.onTrace("Leader 正在移交给专家 Agent。");
      } else if (event.type === "agent_updated_stream_event") {
        const agentName = (event as { agent?: { name?: string } }).agent?.name;
        if (agentName) input.onTrace(`当前执行 Agent：${agentName}`);
      }
    }
    await streamed.completed;
    return streamed;
  }

  try {
    input.onTrace?.("开始运行 OpenAI Agents SDK，等待模型选择专家并调用 case-graph 工具。");
    const contextMessage = input.chatHistory?.length
      ? `之前的对话上下文：\n${input.chatHistory.map((m) => `${m.role === "user" ? "用户" : "Agent"}：${m.content}`).join("\n")}\n\n用户最新回复：${input.question}`
      : input.question;
    let result = await withTrace("pcapAI leader agent", () => runLeaderAgent(contextMessage), {
      groupId: input.graph.spec.caseId,
      metadata: {
        caseId: input.graph.spec.caseId,
        activeQueryRunId: input.graph.activeQueryRunId || "",
        captureCount: String(input.graph.captures.length),
        queryRunCount: String(input.graph.queryRuns.length)
      }
    });
    const toolCalls = extractToolCalls(result);
    // 部分模型会以"纯 <think> 无正文"的消息中途收尾；带上下文追加一轮催收最终 JSON
    const strippedFinal = String(result.finalOutput ?? "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
    if (!strippedFinal && toolCalls.length) {
      input.onTrace?.("模型以思考块收尾且没有正文，追加一轮要求输出最终结论。");
      result = await runner.run(
        leaderAgent,
        result.history.concat({ role: "user", content: "继续：基于已获取的工具结果直接输出最终 JSON 结论，不要再调用工具，不要输出 <think>。" }),
        { maxTurns: 4 }
      );
    }
    input.onTrace?.("Agents SDK 运行完成，正在归一化模型输出为 AgentAnswer。");
    const answer = parseAgentOutput(result.finalOutput);
    return { ...answer, toolCalls };
  } catch (error) {
    // 会话失败可能源于 MCP 连接断开，重置单例让下一次请求重新拉起
    resetTsharkQueryMcp();
    throw error;
  }
}
