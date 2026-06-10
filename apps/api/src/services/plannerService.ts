import type { AgentAnswer, AnalysisChainPlan, AnalysisChainStep, CaseGraph, ChainStepResult } from "../../../../packages/shared/src/index.js";
import { AnalysisChainPlanSchema, ChainStepResultSchema } from "../../../../packages/shared/src/index.js";
import { runChainPlanner, runIntentPlanner, type AgentIntentPlan } from "../agents/runtime.js";

type PlannedResult = { status: string; answer: AgentAnswer } | null;

function patternMatcher(pattern: string) {
  const regex = new RegExp(pattern, "i");
  return (value: string) => regex.test(value);
}

export function createPlannerService(input: {
  fallbackPatterns: {
    usageHelp: string;
    networkStatistics: string;
    selectedSessionDiagnosis: string;
    activeQueryExplain: string;
    reportRequest: string;
    broadTroubleshootingProblem: string;
    concreteTroubleshootingScope: string;
  };
  hasLlmApiKey: () => boolean;
  isProtocolStatisticsQuestion: (question: string) => boolean;
  shouldApplyCorrelationContext: (question: string, graph: CaseGraph) => boolean;
  shouldCorrelateCaptures: (question: string) => boolean;
  shouldCreateQueryRun: (question: string) => boolean;
  executeToolIntent: (graph: CaseGraph, question: string, intent: AgentIntentPlan["intent"], params?: Record<string, unknown>) => Promise<PlannedResult>;
}) {
  const matchesUsageHelp = patternMatcher(input.fallbackPatterns.usageHelp);
  const matchesNetworkStatistics = patternMatcher(input.fallbackPatterns.networkStatistics);
  const matchesSelectedSessionDiagnosis = patternMatcher(input.fallbackPatterns.selectedSessionDiagnosis);
  const matchesActiveQueryExplain = patternMatcher(input.fallbackPatterns.activeQueryExplain);
  const matchesReportRequest = patternMatcher(input.fallbackPatterns.reportRequest);
  const matchesBroadTroubleshootingProblem = patternMatcher(input.fallbackPatterns.broadTroubleshootingProblem);
  const matchesConcreteTroubleshootingScope = patternMatcher(input.fallbackPatterns.concreteTroubleshootingScope);

  function shouldAskForTroubleshootingScope(question: string, graph: CaseGraph) {
    if (graph.queryRuns.length) return false;
    return matchesBroadTroubleshootingProblem(question) && !matchesConcreteTroubleshootingScope(question);
  }

  function fallbackIntentPlan(graph: CaseGraph, question: string): AgentIntentPlan {
    if (matchesUsageHelp(question)) return { intent: "usage_help", confidence: "high", reason: "本地兜底识别为使用帮助。", missingContext: [] };
    if (input.isProtocolStatisticsQuestion(question)) return { intent: "protocol_statistics", confidence: "high", reason: "本地兜底识别为协议统计。", missingContext: [] };
    if (matchesNetworkStatistics(question)) return { intent: "network_statistics", confidence: "medium", reason: "本地兜底识别为确定性统计或事件查询。", missingContext: [] };
    if (input.shouldApplyCorrelationContext(question, graph)) return { intent: "mapping_hint_update", confidence: "medium", reason: "本地兜底识别为多文件关联上下文补充。", missingContext: [] };
    if (input.shouldCorrelateCaptures(question)) return { intent: "capture_correlation", confidence: "medium", reason: "本地兜底识别为多文件关联。", missingContext: [] };
    if (input.shouldCreateQueryRun(question)) return { intent: "tcp_session_query", confidence: "medium", reason: "本地兜底识别为访问链路查询。", missingContext: [] };
    if (graph.queryRuns.length && matchesSelectedSessionDiagnosis(question)) return { intent: "selected_session_diagnosis", confidence: "medium", reason: "本地兜底识别为当前 session 诊断追问。", missingContext: [] };
    if (graph.queryRuns.length && matchesActiveQueryExplain(question)) return { intent: "active_query_explain", confidence: "medium", reason: "本地兜底识别为当前 QueryRun 解释。", missingContext: [] };
    if (matchesReportRequest(question)) return { intent: "report_request", confidence: "medium", reason: "本地兜底识别为报告请求。", missingContext: [] };
    if (shouldAskForTroubleshootingScope(question, graph)) {
      return {
        intent: "needs_clarification",
        confidence: "medium",
        reason: "本地兜底识别为宽泛排障问题。",
        missingContext: ["故障时间段", "源 IP", "目的 IP", "端口", "故障现象类型"]
      };
    }
    return { intent: "llm_explain", confidence: "low", reason: "本地兜底未识别到确定性工具意图。", missingContext: [] };
  }

  async function planUserIntent(graph: CaseGraph, question: string, onTrace?: (message: string) => void, chatHistory?: Array<{ role: string; content: string }>) {
    if (!input.hasLlmApiKey()) {
      throw new Error("未配置 LLM API Key，无法启动 Agent 意图规划。");
    }
    try {
      return await runIntentPlanner({ graph, question, chatHistory, onTrace });
    } catch (error) {
      onTrace?.(`Leader Intent Planner 调用失败：${error instanceof Error ? error.message : String(error)}。`);
      throw error;
    }
  }

  function fallbackChainPlan(graph: CaseGraph, question: string): AnalysisChainPlan {
    const intentPlan = fallbackIntentPlan(graph, question);
    return AnalysisChainPlanSchema.parse({
      chainId: `chain-${Date.now()}`,
      planKind: "single",
      question,
      steps: [{ stepId: "step-0", intent: intentPlan.intent, purpose: intentPlan.reason }],
      confidence: intentPlan.confidence,
      reason: intentPlan.reason,
      missingContext: intentPlan.missingContext
    });
  }

  async function planChain(graph: CaseGraph, question: string, onTrace?: (message: string) => void, chatHistory?: Array<{ role: string; content: string }>): Promise<AnalysisChainPlan> {
    if (!input.hasLlmApiKey()) {
      throw new Error("未配置 LLM API Key，无法启动 Agent 分析链规划。");
    }
    try {
      return await runChainPlanner({ graph, question, chatHistory, onTrace });
    } catch (error) {
      onTrace?.(`Chain Planner 调用失败：${error instanceof Error ? error.message : String(error)}。`);
      throw error;
    }
  }

  async function executeChainStep(graph: CaseGraph, question: string, intent: string, params: Record<string, unknown>): Promise<PlannedResult> {
    const stepQuestion = typeof params.question === "string" ? params.question : (typeof params.purpose === "string" ? params.purpose : question);
    return input.executeToolIntent(graph, stepQuestion, intent as AgentIntentPlan["intent"], params);
  }

  async function executeAgentIntentPlan(graph: CaseGraph, question: string, plan: AgentIntentPlan): Promise<PlannedResult> {
    return input.executeToolIntent(graph, question, plan.intent);
  }

  return {
    shouldAnswerUsageHelp: matchesUsageHelp,
    shouldAnswerActiveQueryRun: matchesActiveQueryExplain,
    shouldExplainSelectedSessionProblem: matchesSelectedSessionDiagnosis,
    shouldAskForTroubleshootingScope,
    fallbackIntentPlan,
    fallbackChainPlan,
    planUserIntent,
    planChain,
    executeAgentIntentPlan,
    executeChainStep
  };
}

export type ChainCallbacks = {
  onStepStart?: (step: AnalysisChainStep, index: number, total: number) => void;
  onStepDone?: (step: AnalysisChainStep, result: ChainStepResult, index: number, total: number) => void;
  onError?: (step: AnalysisChainStep, error: unknown, index: number, total: number) => void;
};

function resolveValueFromPath(obj: unknown, path: string): unknown {
  const segments = path.replace(/\[(\d+)]/g, ".$1").split(".");
  let current = obj;
  for (const segment of segments) {
    if (current === null || current === undefined) return undefined;
    if (Array.isArray(current)) {
      const index = Number(segment);
      current = Number.isFinite(index) ? current[index] : undefined;
    } else if (typeof current === "object") {
      current = (current as Record<string, unknown>)[segment];
    } else {
      return undefined;
    }
  }
  return current;
}

function resolveStepParams(
  step: AnalysisChainStep,
  previousResults: ChainStepResult[]
): Record<string, unknown> {
  const resolved: Record<string, unknown> = { ...step.params };
  if (!step.paramsFrom) return resolved;
  for (const [key, path] of Object.entries(step.paramsFrom)) {
    const stepMatch = path.match(/^step-(\d+)\.(.+)$/);
    if (!stepMatch) continue;
    const stepIndex = Number(stepMatch[1]);
    const fieldPath = stepMatch[2];
    const sourceResult = previousResults[stepIndex];
    if (!sourceResult) continue;
    // 优先在结构化 data 上解析（planner 的路径表达式形如 step-0.dstIp），再回退到完整结果对象
    const value = sourceResult.data ? resolveValueFromPath(sourceResult.data, fieldPath) ?? resolveValueFromPath(sourceResult, fieldPath) : resolveValueFromPath(sourceResult, fieldPath);
    if (value !== undefined) resolved[key] = value;
  }
  return resolved;
}

// 从执行后的 case graph 提取本步骤的结构化事实，供后续步骤 paramsFrom 绑定
function chainStepData(graph: CaseGraph): Record<string, unknown> | undefined {
  const queryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns[graph.queryRuns.length - 1];
  if (!queryRun) return undefined;
  const conversation = queryRun.conversations.find((item) => item.conversationId === queryRun.selectedConversationId) || queryRun.conversations[0];
  // 协议事件查询没有 TCP 会话时，从 dns_to_tcp 关联提取解析 IP 作为绑定源
  const resolvedIps = [...new Set(queryRun.protocolCorrelations
    .filter((correlation) => correlation.kind === "dns_to_tcp")
    .map((correlation) => correlation.targetDisplayFilter.match(/ip\.addr == ((?:\d{1,3}\.){3}\d{1,3})/)?.[1])
    .filter((ip): ip is string => Boolean(ip)))];
  const entries = Object.entries({
    srcIp: conversation?.srcIp,
    dstIp: conversation?.dstIp || resolvedIps[0],
    srcPort: conversation?.srcPort,
    dstPort: conversation?.dstPort,
    port: conversation?.dstPort,
    protocol: queryRun.protocol,
    displayFilter: queryRun.displayFilter,
    resolvedIps: resolvedIps.length ? resolvedIps : undefined
  }).filter(([, value]) => value !== undefined && value !== "");
  return entries.length ? Object.fromEntries(entries) : undefined;
}

export async function executeChain(
  graph: CaseGraph,
  plan: AnalysisChainPlan,
  executeStep: (graph: CaseGraph, intent: string, params: Record<string, unknown>) => Promise<{ status: string; answer: AgentAnswer } | null>,
  callbacks?: ChainCallbacks,
  reloadGraph?: () => CaseGraph
): Promise<{ results: ChainStepResult[]; finalAnswer: AgentAnswer }> {
  let currentGraph = graph;
  const results: ChainStepResult[] = [];
  for (let index = 0; index < plan.steps.length; index++) {
    const step = plan.steps[index];
    callbacks?.onStepStart?.(step, index, plan.steps.length);
    const startedAt = Date.now();
    try {
      const params = resolveStepParams(step, results);
      if (!params.question && !params.purpose) params.purpose = step.purpose;
      const result = await executeStep(currentGraph, step.intent, params);
      if (reloadGraph) currentGraph = reloadGraph();
      const durationMs = Date.now() - startedAt;
      const stepResult = ChainStepResultSchema.parse({
        stepId: step.stepId,
        intent: step.intent,
        status: result?.status || "skipped",
        answer: result?.answer || { answer: "此步骤未产生结果。", evidenceIds: [], packetIds: [], sessionLinkIds: [], findingIds: [], missingContext: [], suggestedActions: [] },
        data: chainStepData(currentGraph),
        durationMs
      });
      results.push(stepResult);
      callbacks?.onStepDone?.(step, stepResult, index, plan.steps.length);
    } catch (error) {
      const durationMs = Date.now() - startedAt;
      const stepResult = ChainStepResultSchema.parse({
        stepId: step.stepId,
        intent: step.intent,
        status: "error",
        answer: {
          answer: `步骤执行失败：${error instanceof Error ? error.message : String(error)}`,
          evidenceIds: [],
          packetIds: [],
          sessionLinkIds: [],
          findingIds: [],
          missingContext: [],
          suggestedActions: [],
          confidence: "low"
        },
        durationMs
      });
      results.push(stepResult);
      callbacks?.onError?.(step, error, index, plan.steps.length);
    }
  }
  const finalAnswer = aggregateChainResults(plan, results);
  return { results, finalAnswer };
}

function aggregateChainResults(plan: AnalysisChainPlan, results: ChainStepResult[]): AgentAnswer {
  if (results.length === 1) return results[0].answer;
  const lines = [
    `分析链完成（${results.length} 步）：`,
    ...results.map((result, index) => {
      const step = plan.steps[index];
      return `\n### 步骤 ${index + 1}：${step.purpose}\n${result.answer.answer}`;
    })
  ];
  return {
    answer: lines.join("\n"),
    thoughts: results.flatMap((result) => result.answer.thoughts || []),
    evidenceCards: results.flatMap((result) => result.answer.evidenceCards || []),
    actions: results.flatMap((result) => result.answer.actions || []),
    evidenceIds: results.flatMap((result) => result.answer.evidenceIds),
    packetIds: results.flatMap((result) => result.answer.packetIds),
    sessionLinkIds: results.flatMap((result) => result.answer.sessionLinkIds),
    findingIds: results.flatMap((result) => result.answer.findingIds),
    missingContext: results.flatMap((result) => result.answer.missingContext),
    // 任一步骤置信度缺失或偏低时保守聚合为 low，不高估整体结论
    confidence: results.every((result) => result.answer.confidence === "certain") ? "certain" : results.some((result) => !result.answer.confidence || result.answer.confidence === "low" || result.answer.confidence === "needs_context") ? "low" : "high",
    suggestedActions: results.flatMap((result) => result.answer.suggestedActions),
    handoffAgent: results[results.length - 1]?.answer.handoffAgent
  };
}
