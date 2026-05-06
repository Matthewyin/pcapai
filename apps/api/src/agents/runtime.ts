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
  chatHistory?: Array<{ role: "user" | "assistant"; content: string }>;
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
      "- protocol_event_query：用户要求列出 DNS/HTTP/TLS/ICMP/UDP/RST/重传/Zero Window/包级事件或前 N 个异常 session。即使问题同时提到多种协议，也只选一个 intent——选择用户最关注的那种协议。",
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
  input.onTrace?.(`Chain Planner 使用模型：${apiConfig.llm.model}，端点：${apiConfig.llm.baseURL}`);
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
      "- protocol_event_query：列出 DNS/HTTP/TLS/ICMP/UDP/RST/重传/Zero Window 事件。每个 step 的 purpose 应只涉及一种协议或一种事件类型（如 \"查询 DNS 解析异常\" 或 \"查看 RST 通信对\"），不要在同一个 step 同时查询多种协议。如需查询多种协议，拆成多个 step。",
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

export type AgentAnswerWithToolCalls = AgentAnswer & { toolCalls?: string[] };

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
  input.onTrace?.(`Agent 使用模型：${apiConfig.llm.model}，端点：${apiConfig.llm.baseURL}`);
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: apiConfig.llm.apiKey,
    baseURL: apiConfig.llm.baseURL,
    useResponses: apiConfig.llm.useResponses
  }));

  const tempDirectory = mkdtempSync(path.join(tmpdir(), "pcapai-case-graph-"));
  const caseGraphPath = path.join(tempDirectory, "case.json");
  // 精简 agent 图谱：移除 insights 和 queryRuns 中的大数据字段，防止 LLM context 超限
  const slimQueryRuns = input.graph.queryRuns.map((qr) => ({
    ...qr,
    conversations: qr.conversations?.map((c) => ({
      conversationId: c.conversationId,
      srcIp: c.srcIp, srcPort: c.srcPort, dstIp: c.dstIp, dstPort: c.dstPort,
      protocol: c.protocol, packetCount: c.packetCount, byteCount: c.byteCount
    })) || [],
    candidateGroups: qr.candidateGroups?.map((g) => ({
      groupId: g.groupId, conversationIds: g.conversationIds
    })) || [],
    evidenceCards: qr.evidenceCards?.map((ec) => ({
      cardId: ec.cardId, kind: ec.kind, title: ec.title, displayFilter: ec.displayFilter
    })) || []
  }));
  const agentGraph = { ...input.graph, insights: [], queryRuns: slimQueryRuns };
  writeFileSync(caseGraphPath, JSON.stringify(agentGraph));
  input.onTrace?.(`已生成只读 case graph 快照：${input.graph.spec.caseId}，captures=${input.graph.captures.length}，queryRuns=${input.graph.queryRuns.length}。`);
  const caseGraphMcp = new MCPServerStdio({
    name: "case-graph-mcp",
    command: apiConfig.caseGraphMcp.command,
    args: apiConfig.caseGraphMcp.args,
    cwd: apiConfig.caseGraphMcp.cwd,
    env: { ...processEnv(), PCAPAI_CASE_GRAPH_PATH: caseGraphPath },
    cacheToolsList: true
  });

  const tsharkQueryMcp = new MCPServerStdio({
    name: "tshark-query-mcp",
    command: apiConfig.tsharkQueryMcp.command,
    args: apiConfig.tsharkQueryMcp.args,
    cwd: apiConfig.tsharkQueryMcp.cwd,
    cacheToolsList: true
  });

  input.onTrace?.("正在连接 case-graph MCP 和 tshark-query MCP。");
  await caseGraphMcp.connect();
  await tsharkQueryMcp.connect();
  input.onTrace?.("case-graph MCP 和 tshark-query MCP 已连接。");

  const mcpServers = [caseGraphMcp, tsharkQueryMcp];

  const triageAgent = new Agent({
    name: "DiagnosticInterviewAgent",
    instructions: [
      "你是 pcapAI 的诊断访谈专家。你的职责是通过多轮对话收集故障信息和网络拓扑。",
      "",
      "## 诊断访谈流程",
      "",
      "### 第一步：症状收集",
      "先调用 load_case_graph 了解当前 case 的情况。然后根据对话历史判断用户是否已描述清楚故障现象：",
      "- 故障现象是什么？（超时、断连、慢、错误、间歇性）",
      "- 受影响的服务/IP/端口？",
      "- 什么时候开始的？持续还是间歇性？",
      "- 影响范围？所有用户还是部分？",
      "",
      "### 第二步：网络拓扑收集",
      "症状清楚后，追问网络路径：",
      "- 客户端到服务端经过了哪些设备？（防火墙、LB、WAF、SSL 卸载、代理、NAT 网关）",
      "- 每个设备的关键配置？",
      "  - 防火墙：NAT 规则、ACL、会话超时",
      "  - 负载均衡：算法、健康检查、会话保持、TCP profile",
      "  - SSL：证书、协议版本",
      "  - WAF：规则集、拦截模式",
      "- 拓扑信息用 update_network_topology 工具保存",
      "",
      "### 第三步：抓包位置确认",
      "- 每个 pcap 文件是从哪个位置抓的？（客户端侧、服务端侧、LB 前端、LB 后端）",
      "- 多个 pcap 时逐一确认每个文件的抓包位置和方向",
      "- 抓包位置决定如何解读包数据",
      "",
      "### 判断何时结束访谈",
      "- 当用户表达\"没有了\"\"就这些\"\"没更多信息\"时，diagnosticPhase 设为 \"hypothesis\"",
      "- 总结收集到的症状和拓扑，说明接下来会进行假设驱动分析",
      "",
      "### 追问格式",
      "- 每轮最多问 2-3 个问题，不要一次问太多",
      "- followUpQuestions 字段列出下一步要问的问题",
      "- diagnosticPhase 为 \"interview\" 直到信息充分",
      "",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers
  });

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
      "## 数据包洞察（get_insights）",
      "系统已自动运行以下分析，结果在 insights 中：",
      "TCP 分析：",
      "- connection_lifecycle: SYN 无 SYN/ACK、握手后 RST、半关闭",
      "- ack_gap: ACK 缺失 → 重传 → RST/hung（含指数退避检测）",
      "- tcp_timing: RTT 估算、空闲间隔、突发模式",
      "- tcp_window_trend: 接收窗口缩小、Zero Window Probe",
      "- tcp_rst_direction: RST 来源方向分析（中间设备检测）、RST 风暴",
      "- tcp_handshake_retry: SYN/SYNACK 重传、同时打开/关闭",
      "- tcp_delayed_ack: Delayed ACK 模式统计",
      "- tcp_connection_flood: SYN 突发、半开连接聚集",
      "- tcp_segment_anomaly: 小包/超大段异常",
      "- tcp_keepalive: Keep-Alive 探测、超时断开",
      "- tcp_throughput: 吞吐量估算、重传开销、BDP",
      "- tcp_options: SACK 协商、Timestamps、TCP Fast Open",
      "HTTP 分析：",
      "- http_status_chain: 3xx 重定向链、4xx/5xx 聚合、错误突发、重复 URI",
      "- http_header_anomaly: Cookie 缺失/不一致、XFF 多跳、Content-Length 截断、缓存缺失、认证失败、Content-Type 混合、Connection: close、WebSocket 升级、压缩缺失、Host vs SNI 不一致",
      "- http_timing: 慢响应（>3s）、响应延迟聚合",
      "TLS 分析：",
      "- tls_handshake: Alert 告警、握手失败原因、握手阶段缺失、TLS 版本降级、弱加密套件、证书 SAN 不匹配、会话恢复、ALPN 协商、TLS 重协商",
      "ICMP 高级分析：",
      "- icmp_echo_pair: Echo/Reply 精确配对（基于 Identifier+Sequence）、RTT、丢包率、抖动",
      "- icmp_unreachable: Unreachable 子类型分析（Port/Host/Network/Fragmentation Needed）、突发检测、错误与 TCP 流关联、Traceroute 模式识别",
      "- icmp_mtu: Path MTU Discovery 黑洞检测、Fragmentation Needed 事件",
      "- icmp_redirect: Redirect 消息检测、路由异常",
      "DNS 高级分析：",
      "- dns_anomaly: NXDOMAIN、SERVFAIL、无响应、慢解析、RCODE 异常",
      "- dns_anomaly（高级）: 查询突发、响应成功率、重复域名、服务器分布、AXFR/IXFR、TTL 异常、CNAME 链、截断响应、NODATA 响应",
      "UDP 分析：",
      "- udp_anomaly: UDP 端口扫描、UDP Flood、单向上行流、有效载荷异常、QUIC 协议检测",
      "- udp_flow: UDP 端点对聚合、流量分布",
      "QUIC 分析：",
      "- quic_anomaly: QUIC 连接概览、握手状态、版本不匹配",
      "NTP 分析：",
      "- ntp_anomaly: Stratum 分布、Root Delay、时间源质量",
      "SSH 分析：",
      "- ssh_anomaly: 消息类型分布、连接断开、认证失败重试、协议版本",
      "跨协议：",
      "- cross_protocol_chain: DNS→TCP→TLS→HTTP 全链路时序分解",
      "直接引用 insights 中的描述和场景，不要重复查询已有结论。",
      "",
      "## 可用的 tshark-query 工具",
      "- list_tcp_resets / list_tcp_retransmissions / list_tcp_zero_window：TCP 异常",
      "- list_dns_packets / list_tls_packets / list_http_packets / list_icmp_events / list_udp_packets：协议事件",
      "- get_expert_info：tshark 专家分析（重传、乱序、重复 ACK、零窗口、丢失段等）",
      "- query_packets / build_display_filter：通用查询",
      "- get_network_statistics：网络统计",
      "capturesJson 参数从 case graph 的 captures 字段获取。",
      "",
      "## 常见假设与预测",
      "| 假设 | 预测在包数据中看到 | 优先检查 insight 类型 | 备用查询工具 |",
      "| 服务端瓶颈 | Zero Window、慢响应、无响应 | ack_gap, http_timing, tcp_window_trend | list_tcp_zero_window + list_http_packets |",
      "| 网络丢包 | 重传、RTT 波动 | ack_gap, tcp_timing, icmp_echo_pair, tcp_throughput | list_tcp_retransmissions |",
      "| 中间设备 RST | 来自非端点的 RST | tcp_rst_direction, connection_lifecycle | list_tcp_resets（分析方向）|",
      "| SSL/TLS 问题 | Alert、握手失败、弱加密 | tls_handshake, cross_protocol_chain | list_tls_packets |",
      "| 证书问题 | SAN 不匹配、证书过期 | tls_handshake（证书分析）| list_tls_packets |",
      "| DNS 问题 | NXDOMAIN、SERVFAIL、无响应 | dns_anomaly | list_dns_packets |",
      "| 应用层慢 | HTTP 响应延迟 | http_timing, cross_protocol_chain | list_http_packets |",
      "| 连接挂起 | ACK 缺失、重传后 RST | ack_gap, tcp_keepalive | query_packets |",
      "| 重定向异常 | 3xx 循环、多次重定向 | http_status_chain | list_http_packets |",
      "| 认证失败 | 401/403、Cookie 缺失 | http_header_anomaly | list_http_packets |",
      "| 性能问题 | 高延迟、低吞吐 | tcp_throughput, tcp_delayed_ack, tcp_timing | get_network_statistics |",
      "| SYN Flood | 大量 SYN 无响应 | tcp_connection_flood | query_packets(SYN) |",
      "| 连接超时 | Keep-Alive 失败、空闲断开 | tcp_keepalive, tcp_window_trend | query_packets |",
      "| 压缩/缓存问题 | 未压缩大响应、无缓存头 | http_header_anomaly | list_http_packets |",
      "| UDP 端口扫描 | 大量不同目标端口的 UDP 包 | udp_anomaly | list_udp_packets |",
      "| UDP Flood | 单端口高频 UDP 突发 | udp_anomaly | list_udp_packets |",
      "| QUIC 连接异常 | QUIC 版本不匹配、连接失败 | udp_anomaly | list_udp_packets |",
      "| ICMP 黑洞 | PMTU 失败、Fragmentation Needed 被丢弃 | icmp_mtu, icmp_unreachable | list_icmp_events |",
      "| Traceroute 问题 | TTL Exceeded 不完整、路径不对称 | icmp_unreachable | list_icmp_events |",
      "| DNS 放大攻击 | 大量 DNS 查询突发、高查询率 | dns_anomaly | list_dns_packets |",
      "| DNS 劫持 | 相同域名多服务器返回不同结果 | dns_anomaly | list_dns_packets |",
      "| DNS 隧道 | 查询突发、异常域名模式 | dns_anomaly | list_dns_packets |",
      "| QUIC 握手失败 | Initial 无 Handshake 响应 | quic_anomaly | list_udp_packets |",
      "| 时间同步问题 | NTP Stratum 高、延迟大 | ntp_anomaly | get_expert_info |",
      "| SSH 连接异常 | 认证重试、断开消息 | ssh_anomaly | get_expert_info |",
      "| PMTU 黑洞 | ICMP Fragmentation Needed + TCP 重传 | icmp_to_tcp, ack_gap | list_icmp_events |",
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
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers
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
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers
  });

  const protocolAgent = new Agent({
    name: "ProtocolAgent",
    instructions: [
      "你是 pcapAI 的协议专项诊断专家，具备网络拓扑感知和假设验证能力。",
      "必须先调用 load_case_graph，再调用 get_network_topology 了解网络设备和抓包位置。",
      "然后调用 get_active_query_run、get_protocol_correlations、get_evidence_cards 和 get_query_diagnosis。",
      "当需要查询原始协议数据（如 TCP RST、重传、Zero Window、DNS、TLS、HTTP、ICMP、UDP 包）时，直接调用 tshark-query MCP 的工具。调用时 capturesJson 参数从 case graph 的 captures 字段获取（JSON 字符串化的 [{nodeId, pcapFilename}] 数组）。",
      "可用的 tshark-query 工具包括：list_tcp_resets、list_tcp_retransmissions、list_tcp_zero_window、list_dns_packets、list_tls_packets、list_http_packets、list_icmp_events、list_udp_packets、query_packets、build_display_filter、get_network_statistics。",
      "解释完协议关联后，调用 suggest_next_query 获取后续查询建议，将结果放入 suggestedQueries 字段。",
      "用户询问 DNS、TLS、SSL、SNI、HTTP、Host、URI、状态码、ICMP、UDP 或 L7 与 TCP 的关系时，优先使用 protocolCorrelations。",
      "只解释 DNS-to-TCP、TLS-SNI-to-TCP、HTTP-Host-to-TCP 的确定性关联，不自动推断 SSL 卸载、Cookie 会话保持或后端连接池。",
      "结合拓扑信息分析协议行为：如果中间有 SSL 卸载设备，客户端侧会看到 TLS，服务端侧会看到明文 HTTP。",
      "如果缺少 protocolCorrelations，要说明当前 QueryRun 没有生成 L7-to-TCP 关联，并建议补充协议查询或过滤条件。",
      "回答必须引用 QueryRun、protocolCorrelation、evidenceCards 或 packetIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers
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
    mcpServers
  });

  const leaderAgent = new Agent({
    name: "PcapTroubleshootingLeaderAgent",
    instructions: [
      "你是 pcapAI 的网络排障诊断 leader。你的工作不是翻译 tshark 输出，而是像高级网络工程师一样诊断故障。",
      "",
      "## 诊断流程",
      "",
      "根据对话上下文判断当前处于哪个诊断阶段，选择对应的专家：",
      "",
      "### 阶段 1：症状收集（interview）",
      "用户第一次提问时，如果还没有描述清楚故障现象，交给 DiagnosticInterviewAgent 收集：",
      "- 故障现象（超时、断连、慢、错误、间歇性）",
      "- 受影响的服务/IP/端口",
      "- 时间范围、频率",
      "- 影响范围",
      "diagnosticPhase 为 \"interview\"。",
      "",
      "### 阶段 2：拓扑 + 抓包位置收集（interview）",
      "症状清楚后，交给 DiagnosticInterviewAgent 收集网络拓扑：",
      "- 网络路径经过了哪些设备（防火墙、LB、WAF、SSL、代理、NAT）",
      "- 每个设备的配置（NAT 规则、TCP profile、SSL 证书、会话超时等）",
      "- 每个 pcap 文件的抓包位置（客户端侧/服务端侧/设备前后）",
      "diagnosticPhase 为 \"interview\"。",
      "",
      "### 阶段 3：假设驱动分析（hypothesis + testing）",
      "当用户表达\"没有了\"\"就这些\"时，交给 HypothesisAgent 进行假设驱动分析：",
      "- 基于症状 + 拓扑形成 2-4 个假设",
      "- 每个假设预测在包数据中会看到什么",
      "- 用 tshark-query MCP 查询证据",
      "- 确认或排除假设",
      "diagnosticPhase 为 \"hypothesis\" 或 \"testing\"。",
      "",
      "### 阶段 4：结论（conclusion）",
      "diagnosticPhase 为 \"conclusion\"。给出因果链和针对性建议。",
      "",
      "## 专家选择规则",
      "- 信息不足、需要追问 → DiagnosticInterviewAgent",
      "- 假设验证、因果链分析 → HypothesisAgent",
      "- 多节点路径、断点分析 → PathAgent",
      "- DNS/TLS/HTTP/ICMP/UDP 协议专项 → ProtocolAgent",
      "- 生成报告 → ReportAgent",
      "- 统计类问题、时间范围 → HypothesisAgent（使用 get_case_statistics）",
      "",
      "## 关键规则",
      "- 不要翻译 tshark 输出。要解释证据与故障的关系。",
      "- 不允许编造包、节点或结论。没有证据支持的假设不要当成结论。",
      "- 当信息不足时，返回 followUpQuestions，不要猜测。",
      "- 输出必须绑定 QueryRun、evidenceIds、packetIds 等可回溯 ID。",
      jsonOutputInstruction
    ].join("\n"),
    handoffs: [triageAgent, evidenceAgent, pathAgent, protocolAgent, reportAgent],
    model: apiConfig.llm.model,
    modelSettings: modelSettings(),
    mcpServers
  });
  input.onTrace?.(`已创建 Leader Agent 和 5 个专家 Agent，模型=${apiConfig.llm.model}。`);

  try {
    input.onTrace?.("开始运行 OpenAI Agents SDK，等待模型选择专家并调用 case-graph 工具。");
    const contextMessage = input.chatHistory?.length
      ? `之前的对话上下文：\n${input.chatHistory.map((m) => `${m.role === "user" ? "用户" : "Agent"}：${m.content}`).join("\n")}\n\n用户最新回复：${input.question}`
      : input.question;
    const result = await withTrace("pcapAI leader agent", () => run(leaderAgent, contextMessage, { maxTurns: 16 }), {
      groupId: input.graph.spec.caseId,
      metadata: {
        caseId: input.graph.spec.caseId,
        activeQueryRunId: input.graph.activeQueryRunId || "",
        captureCount: String(input.graph.captures.length),
        queryRunCount: String(input.graph.queryRuns.length)
      }
    });
    input.onTrace?.("Agents SDK 运行完成，正在归一化模型输出为 AgentAnswer。");
    const answer = parseAgentOutput(result.finalOutput);
    const toolCalls = extractToolCalls(result);
    return { ...answer, toolCalls };
  } finally {
    await tsharkQueryMcp.close();
    await caseGraphMcp.close();
    rmSync(tempDirectory, { recursive: true, force: true });
    input.onTrace?.("MCP 已关闭，临时 case graph 快照已清理。");
  }
}
