import type { AgentAnswer, AnalysisChainPlan, AnalysisChainStep, CaseGraph, ChainStepResult } from "../../../../packages/shared/src/index.js";
import { ChainStepResultSchema } from "../../../../packages/shared/src/index.js";
import { runChainPlanner, type AgentIntentPlan } from "../agents/runtime.js";

type PlannedResult = { status: string; answer: AgentAnswer } | null;

export function createPlannerService(input: {
  hasLlmApiKey: () => boolean;
  executeToolIntent: (graph: CaseGraph, question: string, intent: AgentIntentPlan["intent"], params?: Record<string, unknown>) => Promise<PlannedResult>;
}) {
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
    const dotIndex = path.indexOf(".");
    if (dotIndex <= 0) continue;
    const stepRef = path.slice(0, dotIndex);
    const fieldPath = path.slice(dotIndex + 1);
    // 优先按 stepId 精确匹配，避免 stepId 命名与数组下标错位；找不到再退回数字下标
    const indexMatch = stepRef.match(/^step-(\d+)$/);
    const sourceResult = previousResults.find((result) => result.stepId === stepRef)
      || (indexMatch ? previousResults[Number(indexMatch[1])] : undefined);
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
      const prevActiveQueryRunId = currentGraph.activeQueryRunId;
      const prevQueryRunCount = currentGraph.queryRuns.length;
      const result = await executeStep(currentGraph, step.intent, params);
      if (reloadGraph) currentGraph = reloadGraph();
      // 只有本步骤实际产生了新 QueryRun 才暴露结构化数据，避免把上一步的结果错绑给 paramsFrom
      const producedQueryRun = currentGraph.activeQueryRunId !== prevActiveQueryRunId || currentGraph.queryRuns.length > prevQueryRunCount;
      const durationMs = Date.now() - startedAt;
      const stepResult = ChainStepResultSchema.parse({
        stepId: step.stepId,
        intent: step.intent,
        status: result?.status || "skipped",
        answer: result?.answer || { answer: "此步骤未产生结果。", evidenceIds: [], packetIds: [], sessionLinkIds: [], findingIds: [], missingContext: [], suggestedActions: [] },
        data: producedQueryRun ? chainStepData(currentGraph) : undefined,
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
    // 置信度聚合：全 certain 才 certain；显式 low/needs_context 拉低为 low；
    // 缺失置信度（很多确定性 adapter 默认不设）视为 neutral，不拖累整体结论
    confidence: results.every((result) => result.answer.confidence === "certain")
      ? "certain"
      : results.some((result) => result.answer.confidence === "low" || result.answer.confidence === "needs_context")
        ? "low"
        : "high",
    suggestedActions: results.flatMap((result) => result.answer.suggestedActions),
    handoffAgent: results[results.length - 1]?.answer.handoffAgent
  };
}
