import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Agent, MCPServerStdio, OpenAIProvider, run, setDefaultModelProvider, tool, withTrace } from "@openai/agents";
import { z } from "zod";
import { AgentIntentEnum, AnalysisChainPlanSchema, type AgentAnswer, type AnalysisChainPlan, type AnalysisChainStep, type CaseGraph } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

type RuntimeInput = {
  graph: CaseGraph;
  question: string;
  onTrace?: (message: string) => void;
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

type IntentPlannerInput = {
  graph: CaseGraph;
  question: string;
  onTrace?: (message: string) => void;
};

type CompatibilityInput = {
  apiKey: string;
  baseURL: string;
  model: string;
  providerData: Record<string, unknown>;
};

const jsonOutputInstruction = [
  "最终只能输出一个 JSON 对象，不要使用 Markdown。",
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
  const lines = [answer.answer.trim() || "当前没有形成可解释的结论。"];
  if (answer.confidence) lines.push("", `置信度：${answer.confidence}`);
  if (answer.missingContext.length) {
    lines.push("", "缺失上下文：", ...answer.missingContext.map((item) => `- ${item}`));
  }
  if (answer.suggestedActions.length) {
    lines.push("", "建议动作：", ...answer.suggestedActions.map((item) => `- ${item}`));
  }
  const references = [
    answer.findingIds.length ? `finding: ${answer.findingIds.join(", ")}` : "",
    answer.evidenceIds.length ? `evidence: ${answer.evidenceIds.join(", ")}` : "",
    answer.sessionLinkIds.length ? `sessionLink: ${answer.sessionLinkIds.join(", ")}` : "",
    answer.packetIds.length ? `packet: ${answer.packetIds.join(", ")}` : ""
  ].filter(Boolean);
  if (references.length) lines.push("", "证据引用：", ...references.map((item) => `- ${item}`));
  if (answer.handoffAgent) lines.push("", `处理 Agent：${answer.handoffAgent}`);
  return { ...answer, answer: lines.join("\n") };
}

function normalizeSuggestedQueries(value: unknown): Array<{ question: string; reason: string; intent: string }> {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is Record<string, unknown> => item && typeof item === "object" && typeof item.question === "string").map((item) => ({
    question: String(item.question),
    reason: typeof item.reason === "string" ? item.reason : "",
    intent: typeof item.intent === "string" ? item.intent : "llm_explain"
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
    handoffAgent: typeof value.handoffAgent === "string" && value.handoffAgent.trim() ? value.handoffAgent : undefined
  };
  return formatAgentAnswer(answer);
}

function parseAgentOutput(output: unknown): AgentAnswer {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const jsonText = text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
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

function parseIntentOutput(output: unknown): AgentIntentPlan {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const jsonText = firstJsonObject(text);
  if (!jsonText) throw new Error(`intent planner returned non-json output: ${text.slice(0, 500)}`);
  const parsed = JSON.parse(jsonText);
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const value = parsed as Record<string, unknown>;
    const confidence = typeof value.confidence === "string" ? value.confidence.trim().toLowerCase() : "";
    if (confidence === "certain" || confidence === "confident" || confidence === "确定") value.confidence = "high";
    if (confidence === "needs_context" || confidence === "uncertain" || confidence === "不确定") value.confidence = "low";
    if (value.confidence !== "high" && value.confidence !== "medium" && value.confidence !== "low") value.confidence = "medium";
    if (typeof value.missingContext === "string") value.missingContext = value.missingContext.trim() ? [value.missingContext] : [];
    if (value.missingContext === null || value.missingContext === undefined) value.missingContext = [];
  }
  return AgentIntentSchema.parse(parsed);
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

function intentPlannerContext(graph: CaseGraph, question: string) {
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
    mappingHintCount: graph.mappingHints.length,
    timeOffsetHintCount: graph.timeOffsetHints.length
  };
}

function processEnv() {
  return Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined));
}

function modelSettings() {
  return Object.keys(apiConfig.llm.providerData).length ? { providerData: apiConfig.llm.providerData } : {};
}

function modelSettingsFrom(providerData: Record<string, unknown>) {
  return Object.keys(providerData).length ? { providerData } : {};
}

export async function runIntentPlanner(input: IntentPlannerInput): Promise<AgentIntentPlan> {
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: apiConfig.llm.apiKey,
    baseURL: apiConfig.llm.baseURL,
    useResponses: apiConfig.llm.useResponses
  }));

  const plannerAgent = new Agent({
    name: "PcapIntentPlanner",
    instructions: [
      "你是 pcapAI 的 Leader Intent Planner，只负责理解用户意图，不执行分析，不调用 MCP，不读取 pcap。",
      "你必须输出一个 JSON 对象，不要 Markdown，不要解释。",
      "字段固定为 intent、confidence、reason、missingContext。",
      "intent 只能是：",
      "- usage_help：用户问怎么使用、帮助、流程、怎么开始。",
      "- protocol_statistics：用户问协议种类、协议数量、协议分布。",
      "- network_statistics：用户问 IP 数量、源/目的 IP 排名、端口分布、RST 数量、重传数量、HTTP 状态码分布、DNS rcode 分布等事实统计。",
      "- tcp_session_query：用户给出时间、源/目的、端口，要求分析访问、通信对、TCP session、路径候选。",
      "- protocol_event_query：用户要求列出 DNS/HTTP/TLS/ICMP/UDP/RST/重传/Zero Window/包级事件或前 N 个异常 session。",
      "- capture_correlation：用户问多个 pcap/两个文件/多节点能否串起来、路径还原、跨节点关联。",
      "- mapping_hint_update：用户补充 NAT/F5/LB/SLB/代理/地址转换/时间偏移/节点上下文，用于重跑多文件关联。",
      "- selected_session_diagnosis：用户问当前选中的 session 为什么失败、问题在哪、哪里异常。",
      "- active_query_explain：用户问当前查询、当前证据、当前路径的解释。",
      "- report_request：用户要求生成报告、总结、复盘。",
      "- needs_clarification：用户想排障但缺时间、源、目的、端口、节点等关键条件。",
      "- llm_explain：其他需要自然语言解释且没有明确工具动作的问题。",
      "如果用户的问题是泛化帮助，即使包含“这个”，也必须选 usage_help，不能选 active_query_explain。",
      "如果用户问“多少、几个、分布、排名、列出、有没有某类包”，优先选统计或协议事件工具类 intent。",
      "如果不确定，选 needs_clarification，不要猜具体故障。"
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings()
  });
  input.onTrace?.("Leader Intent Planner 正在判断用户意图。");
  const result = await run(plannerAgent, JSON.stringify(intentPlannerContext(input.graph, input.question)), { maxTurns: 2 });
  const plan = parseIntentOutput(result.finalOutput);
  input.onTrace?.(`Leader Intent Planner 输出：${plan.intent}（${plan.confidence}）- ${plan.reason}`);
  return plan;
}

type ChainPlannerInput = {
  graph: CaseGraph;
  question: string;
  onTrace?: (message: string) => void;
};

export async function runChainPlanner(input: ChainPlannerInput): Promise<AnalysisChainPlan> {
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: apiConfig.llm.apiKey,
    baseURL: apiConfig.llm.baseURL,
    useResponses: apiConfig.llm.useResponses
  }));

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
      "steps 中每个 step 的字段：stepId（\"step-0\", \"step-1\"...）、intent、purpose（中文描述这一步要做什么）。",
      "如果某个 step 的查询参数来自前序 step 的结果，用 paramsFrom 字段表达。",
      "paramsFrom 的 key 是查询参数名（srcIp, dstIp, port, protocol），value 是路径表达式如 \"step-0.dstIp\"。",
      "",
      "intent 只能是以下之一：",
      "- usage_help：用户问怎么使用、帮助、流程。",
      "- protocol_statistics：协议种类、数量、分布。",
      "- network_statistics：IP/端口/RST/重传/状态码等事实统计。",
      "- tcp_session_query：分析访问、TCP session、路径候选。",
      "- protocol_event_query：列出 DNS/HTTP/TLS/ICMP/UDP/RST/重传/Zero Window 事件。",
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
      "重要：当用户问题是开放性分析问题（如\"分析异常\"、\"有什么问题\"、\"帮我看看\"）时，必须先安排确定性步骤收集证据，最后一步必须是 llm_explain 来综合解读证据并给出诊断结论。",
      "llm_explain 步骤的 purpose 应描述为\"综合解读前序步骤的证据，给出诊断结论和建议\"。",
      "纯统计问题（如\"协议分布\"、\"端口排名\"）不需要 llm_explain。"
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings()
  });
  input.onTrace?.("Chain Planner 正在规划分析步骤。");
  const result = await run(chainPlannerAgent, JSON.stringify(intentPlannerContext(input.graph, input.question)), { maxTurns: 2 });
  const plan = parseChainPlanOutput(result.finalOutput, input.question);
  const stepSummary = plan.steps.map((step: AnalysisChainStep) => `${step.intent}(${step.purpose})`).join(" → ");
  input.onTrace?.(`Chain Planner 输出：${plan.planKind}（${plan.confidence}）${stepSummary}`);
  return plan;
}

export async function runAgentCompatibilityCheck(input: CompatibilityInput) {
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: input.apiKey,
    baseURL: input.baseURL,
    useResponses: false
  }));

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

  const result = await run(leaderAgent, "执行 Agent 兼容性测试。", { maxTurns: 4 });
  if (!toolCalled) throw new Error("模型没有完成工具调用，Agent 兼容性测试未通过。");
  return { ok: true, output: String(result.finalOutput || "").slice(0, 500) };
}

export async function runPcapTroubleshootingAgent(input: RuntimeInput): Promise<AgentAnswer> {
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: apiConfig.llm.apiKey,
    baseURL: apiConfig.llm.baseURL,
    useResponses: apiConfig.llm.useResponses
  }));

  const tempDirectory = mkdtempSync(path.join(tmpdir(), "pcapai-case-graph-"));
  const caseGraphPath = path.join(tempDirectory, "case.json");
  writeFileSync(caseGraphPath, JSON.stringify(input.graph));
  input.onTrace?.(`已生成只读 case graph 快照：${input.graph.spec.caseId}，captures=${input.graph.captures.length}，queryRuns=${input.graph.queryRuns.length}。`);
  const caseGraphMcp = new MCPServerStdio({
    name: "case-graph-mcp",
    command: apiConfig.caseGraphMcp.command,
    args: apiConfig.caseGraphMcp.args,
    cwd: apiConfig.caseGraphMcp.cwd,
    env: { ...processEnv(), PCAPAI_CASE_GRAPH_PATH: caseGraphPath },
    cacheToolsList: true
  });

  input.onTrace?.("正在连接 case-graph MCP。");
  await caseGraphMcp.connect();
  input.onTrace?.("case-graph MCP 已连接，Agent 只能通过 MCP 读取证据。");

  const triageAgent = new Agent({
    name: "TriageAgent",
    instructions: [
      "你是 pcapAI 的上下文检查专家。",
      "先调用 load_case_graph，只基于工具返回内容判断缺什么信息。",
      "重点检查是否存在 active QueryRun、是否选择了通讯对、抓包节点、接口方向、NAT/SLB/代理线索、时间窗口。",
      "缺少上下文时写入 missingContext 和 suggestedActions。",
      "回答必须是中文，并引用相关 evidenceIds、findingIds 或 sessionLinkIds。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });

  const evidenceAgent = new Agent({
    name: "EvidenceAgent",
    instructions: [
      "你是 pcapAI 的证据解释专家。",
      "必须先调用 load_case_graph，再按需要调用 get_case_statistics、get_active_query_run、get_evidence_cards、get_query_diagnosis、get_finding、get_evidence、get_session_link、get_packet_detail。",
      "解释完证据后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "用户询问 TCP 通信对、连接数、时间范围、时间窗口、统计类问题时，优先调用 get_case_statistics，不能自己估算。",
      "用户询问当前案例所有捕获数据包的整体时间范围时，使用 get_case_statistics 返回的 timeRanges.allCapturedPackets；询问当前筛选结果时间范围时，使用 timeRanges.filteredPackets。",
      "用户询问证据卡、packet、RST、重传、Zero Window 时，优先引用 active QueryRun、evidenceCards 和 selectedDiagnosis.checks。",
      "不允许编造未出现在 case graph 中的包、节点或故障原因。",
      "没有 active QueryRun 或没有选中通讯对时，必须要求用户先提出查询条件或选择通讯对。",
      "回答必须包含可回溯的 QueryRun、Conversation、evidenceIds、packetIds、findingIds 或 sessionLinkIds。低置信度不能说成确定结论。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });

  const pathAgent = new Agent({
    name: "PathAgent",
    instructions: [
      "你是 pcapAI 的多节点路径还原专家。",
      "必须先调用 load_case_graph，再调用 get_path_diagnosis 和 get_query_diagnosis。",
      "解释完路径后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "只解释 PathHop、PathEdge、correlation、edge diagnosis、timeDeltaSeconds、mapping/time offset 依据。",
      "用户询问断点、哪一跳、路径、链路、上游下游、NAT/F5/LB/代理映射时，优先使用 get_path_diagnosis。",
      "如果 path edge 是 needs_context，要明确说需要补充映射、时间偏移、抓包方向或节点顺序；不能说成确定设备故障。",
      "回答必须绑定 QueryRun、PathHop/PathEdge、packetIds、findingIds 或 sessionLinkIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });

  const protocolAgent = new Agent({
    name: "ProtocolAgent",
    instructions: [
      "你是 pcapAI 的协议专项诊断专家。",
      "必须先调用 load_case_graph，再调用 get_active_query_run、get_protocol_correlations、get_evidence_cards 和 get_query_diagnosis。",
      "解释完协议关联后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "用户询问 DNS、TLS、SSL、SNI、HTTP、Host、URI、状态码、ICMP、UDP 或 L7 与 TCP 的关系时，优先使用 protocolCorrelations。",
      "只解释 DNS-to-TCP、TLS-SNI-to-TCP、HTTP-Host-to-TCP 的确定性关联，不自动推断 SSL 卸载、Cookie 会话保持或后端连接池。",
      "如果缺少 protocolCorrelations，要说明当前 QueryRun 没有生成 L7-to-TCP 关联，并建议补充协议查询或过滤条件。",
      "回答必须引用 QueryRun、protocolCorrelation、evidenceCards 或 packetIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });

  const reportAgent = new Agent({
    name: "ReportAgent",
    instructions: [
      "你是 pcapAI 的中文排障报告专家。",
      "必须调用 export_report 获取报告草稿，再按用户问题压缩或解释。",
      "只整理已有 case graph，不新增证据判断。",
      "报告包含：问题现象、路径还原、L7 关联、关键证据、判断结论、下一步动作。",
      "所有结论必须引用 QueryRun、PathEdge、protocolCorrelation、evidenceIds、packetIds、findingIds 或 sessionLinkIds。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });

  const leaderAgent = new Agent({
    name: "PcapTroubleshootingLeaderAgent",
    instructions: [
      "你是 pcapAI 的 leader agent。",
      "根据用户问题选择且只选择一个专家：缺少上下文交给 TriageAgent，包级证据交给 EvidenceAgent，多节点路径和断点交给 PathAgent，DNS/TLS/HTTP/ICMP/UDP 协议问题交给 ProtocolAgent，生成报告交给 ReportAgent。",
      "统计类问题、时间范围、时间窗口问题交给 EvidenceAgent，并要求它使用 get_case_statistics。",
      "访问链路、哪一跳、断点、上下游、mapping hint、time offset 交给 PathAgent。",
      "DNS、TLS、SSL、SNI、HTTP、Host、URI、状态码、ICMP、UDP、L7 到 TCP 关联解释交给 ProtocolAgent。",
      "RST、重传、Zero Window、具体 packet 或证据卡解释交给 EvidenceAgent。",
      "不要直接读取本地文件，不要执行 shell，不要绕过工具。",
      "你只能通过工具读取 case graph，不允许基于常识补造包、节点、转换线索或结论。",
      "输出必须绑定 QueryRun、Conversation、PathHop、protocolCorrelation、evidenceIds、packetIds、findingIds 或 sessionLinkIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    handoffs: [triageAgent, evidenceAgent, pathAgent, protocolAgent, reportAgent],
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers: [caseGraphMcp]
  });
  input.onTrace?.(`已创建 Leader Agent 和 5 个专家 Agent，模型=${apiConfig.llm.model}。`);

  try {
    input.onTrace?.("开始运行 OpenAI Agents SDK，等待模型选择专家并调用 case-graph 工具。");
    const result = await withTrace("pcapAI leader agent", () => run(leaderAgent, input.question, { maxTurns: 8 }), {
      groupId: input.graph.spec.caseId,
      metadata: {
        caseId: input.graph.spec.caseId,
        activeQueryRunId: input.graph.activeQueryRunId || "",
        captureCount: String(input.graph.captures.length),
        queryRunCount: String(input.graph.queryRuns.length)
      }
    });
    input.onTrace?.("Agents SDK 运行完成，正在归一化模型输出为 AgentAnswer。");
    return parseAgentOutput(result.finalOutput);
  } finally {
    await caseGraphMcp.close();
    rmSync(tempDirectory, { recursive: true, force: true });
    input.onTrace?.("case-graph MCP 已关闭，临时 case graph 快照已清理。");
  }
}
