import type { AgentAnswer, AnalysisChainPlan, CaseGraph } from "../../../../packages/shared/src/index.js";
import type { Tool } from "@openai/agents";
import { apiConfig } from "../config.js";
import { runPcapTroubleshootingAgent, type AgentIntentPlan } from "../agents/runtime.js";
import { executeChain } from "./plannerService.js";

type ChatMessage = { role: "user" | "assistant"; content: string };

export type AgentChatRequest = {
  question: string;
  chatHistory: ChatMessage[];
  thinkingDepth?: string;
  reasoningDepth?: string;
};

type PlannedResult = { status: string; answer: AgentAnswer } | null;

type RuntimeStatusPatch = {
  lastRunAt: string;
  lastStatus: string;
  lastError: string;
  lastCaseId: string;
  lastModel: string;
  lastBaseURL: string;
};

type StreamEmitter = {
  event: (event: string, data: unknown) => void;
  thought: (text: string) => void;
  delta: (text: string) => void;
  done: (answer: AgentAnswer) => void;
  error: (error: string) => void;
};

type AgentRuntimeDependencies = {
  planChain: (
    graph: CaseGraph,
    question: string,
    onTrace?: (message: string) => void,
    chatHistory?: ChatMessage[]
  ) => Promise<AnalysisChainPlan>;
  executeAgentIntentPlan: (graph: CaseGraph, question: string, plan: AgentIntentPlan) => Promise<PlannedResult>;
  executeChainStep: (graph: CaseGraph, question: string, intent: string, params: Record<string, unknown>) => Promise<PlannedResult>;
  loadGraph: (caseId: string) => CaseGraph;
  buildAgentQuestion: (input: AgentChatRequest) => string;
  answerWithPlannerThought: (answer: AgentAnswer, plan: AgentIntentPlan) => AgentAnswer;
  diagnosticInterviewAnswer: (graph: CaseGraph, question: string, missingContext?: string[]) => AgentAnswer;
  syncMemoryFromQueryRuns: (graph: CaseGraph) => CaseGraph;
  recordPlannerRun: (caseId: string, question: string, plan: AgentIntentPlan, durationMs: number) => void;
  recordAnswerRun: (caseId: string, question: string, plan: AgentIntentPlan, status: string, answer: AgentAnswer, durationMs: number) => void;
  recordErrorRun: (caseId: string, question: string, plan: AgentIntentPlan, status: string, error: unknown, durationMs: number) => void;
  updateRuntimeStatus: (patch: RuntimeStatusPatch) => void;
  adapterIds: () => string[];
  createAgentTools: (caseId: string, question: string) => Tool[];
  learnFromAgentRun: (question: string, toolCalls: string[], adapterIds: string[]) => void;
  findLearnedBypass: (question: string) => { regex: string; adapterId: string } | null;
};

function singlePlanFromChain(chainPlan: AnalysisChainPlan): AgentIntentPlan {
  return {
    intent: chainPlan.steps[0]?.intent || "llm_explain",
    confidence: chainPlan.confidence,
    reason: chainPlan.reason,
    missingContext: chainPlan.missingContext
  };
}

function statusPatch(graph: CaseGraph, status: string, error = ""): RuntimeStatusPatch {
  return {
    lastRunAt: new Date().toISOString(),
    lastStatus: status,
    lastError: error,
    lastCaseId: graph.spec.caseId,
    lastModel: apiConfig.llm.model,
    lastBaseURL: apiConfig.llm.baseURL
  };
}

function emitAnswerInChunks(emit: StreamEmitter, answer: string) {
  for (let index = 0; index < answer.length; index += 24) {
    emit.delta(answer.slice(index, index + 24));
  }
}

function llmKeyRequiredAnswer(): AgentAnswer {
  return {
    answer: "当前没有配置 LLM API Key，Agent 分析未启动。请先到“设置 → 模型配置”中填写 OpenAI 兼容的 Base URL、API Key 和模型名称，并完成连接测试后再继续分析。",
    thoughts: ["未检测到 LLM API Key，已停止 Agent 编排。"],
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: ["LLM API Key"],
    confidence: "needs_context",
    suggestedActions: [
      "打开设置菜单，进入模型配置。",
      "填写 Base URL、API Key 和模型名称。",
      "点击连接测试，确认模型可用后重新提问。"
    ]
  };
}

function llmKeyRequiredPlan(): AgentIntentPlan {
  return {
    intent: "needs_clarification",
    confidence: "high",
    reason: "缺少 LLM API Key，不能启动 Agent 分析。",
    missingContext: ["LLM API Key"]
  };
}

function shouldInterviewBeforeExecution(graph: CaseGraph, chainPlan: AnalysisChainPlan) {
  const intents = chainPlan.steps.map((step) => step.intent);
  if (!chainPlan.missingContext.length) return false;
  if (intents.every((intent) => intent === "usage_help" || intent === "network_statistics" || intent === "protocol_statistics" || intent === "report_request")) return false;
  if (intents.includes("mapping_hint_update")) return false;
  if (intents.includes("active_query_explain") || intents.includes("selected_session_diagnosis")) return false;
  if (graph.queryRuns.length && intents.every((intent) => intent === "llm_explain")) return false;
  return true;
}

export function createAgentRuntimeService(deps: AgentRuntimeDependencies) {
  // 高命中学习模式直通车：确定性路径直接执行，省一次 planner LLM 调用；未产出结果则回退正常流程
  async function tryLearnedBypass(graph: CaseGraph, request: AgentChatRequest, startedAt: number, onTrace?: (text: string) => void) {
    const bypass = deps.findLearnedBypass(request.question);
    if (!bypass) return null;
    onTrace?.(`命中高置信学习模式（${bypass.adapterId}），跳过分析链规划直接执行。`);
    const plan: AgentIntentPlan = {
      intent: "protocol_event_query",
      confidence: "high",
      reason: `命中高置信学习模式（regex: ${bypass.regex} → ${bypass.adapterId}），跳过规划`,
      missingContext: []
    };
    try {
      const result = await deps.executeChainStep(graph, request.question, "protocol_event_query", {});
      if (!result) return null;
      const answer = deps.answerWithPlannerThought(result.answer, plan);
      deps.recordAnswerRun(graph.spec.caseId, request.question, plan, "learned_bypass", answer, Date.now() - startedAt);
      deps.updateRuntimeStatus(statusPatch(graph, "learned_bypass"));
      deps.syncMemoryFromQueryRuns(deps.loadGraph(graph.spec.caseId));
      return { status: "learned_bypass", answer };
    } catch {
      // 直通失败不致命，回退正常规划流程
      onTrace?.("学习模式直通执行失败，回退到正常规划流程。");
      return null;
    }
  }

  function executeInterview(graph: CaseGraph, request: AgentChatRequest, chainPlan: AnalysisChainPlan, durationMs: number, startedAt: number) {
    const plan = singlePlanFromChain(chainPlan);
    const answer = deps.answerWithPlannerThought(deps.diagnosticInterviewAnswer(graph, request.question, chainPlan.missingContext), plan);
    deps.recordPlannerRun(graph.spec.caseId, request.question, plan, durationMs);
    deps.recordAnswerRun(graph.spec.caseId, request.question, plan, "needs_clarification", answer, Date.now() - startedAt);
    deps.updateRuntimeStatus(statusPatch(graph, "needs_clarification"));
    return { status: "needs_clarification", answer };
  }

  async function runLlmFallback(graph: CaseGraph, request: AgentChatRequest, plan: AgentIntentPlan, onTrace?: (message: string) => void) {
    if (!apiConfig.llm.apiKey) {
      onTrace?.("未配置 LLM API Key，Agent 分析未启动。");
      return { status: "llm_key_required", answer: llmKeyRequiredAnswer() };
    }
    const answer = await runPcapTroubleshootingAgent({
      graph,
      question: deps.buildAgentQuestion(request),
      chatHistory: request.chatHistory,
      onTrace,
      tools: deps.createAgentTools(graph.spec.caseId, request.question)
    });
    // 只学习有据可依的高置信回答，避免低质量回答固化成错误路由
    if ((answer.confidence === "high" || answer.confidence === "certain") && (answer.evidenceCards?.length || answer.packetIds.length)) {
      deps.learnFromAgentRun(request.question, answer.toolCalls || [], deps.adapterIds());
    }
    return { status: plan.intent === "llm_explain" ? "success" : "agent_fallback", answer: deps.answerWithPlannerThought(answer, plan) };
  }

  async function executeSingle(graph: CaseGraph, request: AgentChatRequest, plan: AgentIntentPlan, durationMs: number, startedAt: number, onTrace?: (message: string) => void) {
    try {
      const plannedResult = await deps.executeAgentIntentPlan(graph, request.question, plan);
      if (plannedResult) {
        const answer = deps.answerWithPlannerThought(plannedResult.answer, plan);
        deps.recordPlannerRun(graph.spec.caseId, request.question, plan, durationMs);
        deps.recordAnswerRun(graph.spec.caseId, request.question, plan, plannedResult.status, answer, Date.now() - startedAt);
        deps.updateRuntimeStatus(statusPatch(graph, plannedResult.status));
        deps.syncMemoryFromQueryRuns(deps.loadGraph(graph.spec.caseId));
        return { status: plannedResult.status, answer };
      }
      const fallback = await runLlmFallback(graph, request, plan, onTrace);
      deps.recordPlannerRun(graph.spec.caseId, request.question, plan, durationMs);
      deps.recordAnswerRun(graph.spec.caseId, request.question, plan, fallback.status, fallback.answer, Date.now() - startedAt);
      deps.updateRuntimeStatus(statusPatch(graph, fallback.status));
      deps.syncMemoryFromQueryRuns(deps.loadGraph(graph.spec.caseId));
      return fallback;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      deps.recordPlannerRun(graph.spec.caseId, request.question, plan, durationMs);
      deps.recordErrorRun(graph.spec.caseId, request.question, plan, `${plan.intent}_error`, error, Date.now() - startedAt);
      deps.updateRuntimeStatus(statusPatch(graph, `${plan.intent}_error`, message));
      throw error;
    }
  }

  async function executeChainPlan(graph: CaseGraph, request: AgentChatRequest, chainPlan: AnalysisChainPlan, durationMs: number, startedAt: number, emit?: StreamEmitter) {
    emit?.event("chain_start", { chainId: chainPlan.chainId, stepCount: chainPlan.steps.length });
    const { results, finalAnswer } = await executeChain(
      graph,
      chainPlan,
      (currentGraph, intent, params) => deps.executeChainStep(currentGraph, request.question, intent, params),
      {
        onStepStart: (step, index, total) => {
          emit?.event("step_start", { stepId: step.stepId, intent: step.intent, purpose: step.purpose, index, total });
          emit?.thought(`步骤 ${index + 1}/${total}：${step.purpose}`);
        },
        onStepDone: (step, result, index, total) => {
          emit?.event("step_done", {
            stepId: step.stepId,
            status: result.status,
            summary: result.answer.answer.slice(0, 200),
            index,
            total,
            evidenceCards: result.answer.evidenceCards || [],
            purpose: step.purpose
          });
        },
        onError: (step, error, index, total) => {
          emit?.event("step_done", {
            stepId: step.stepId,
            status: "error",
            summary: `步骤失败：${error instanceof Error ? error.message : String(error)}`,
            index,
            total
          });
        }
      },
      () => deps.loadGraph(graph.spec.caseId)
    );
    const hasLlmStep = chainPlan.steps.some((step) => step.intent === "llm_explain");
    // 纯统计/帮助/报告类的链不需要 LLM 综合解读，与 Chain Planner 的提示词约定保持一致
    const deterministicOnly = chainPlan.steps.every((step) => step.intent === "protocol_statistics" || step.intent === "network_statistics" || step.intent === "usage_help" || step.intent === "report_request");
    let answer = finalAnswer;
    if (!hasLlmStep && !deterministicOnly && apiConfig.llm.apiKey) {
      emit?.thought("综合解读证据，生成诊断结论...");
      try {
        const freshGraph = deps.loadGraph(graph.spec.caseId);
        const llmAnswer = await runPcapTroubleshootingAgent({
          graph: freshGraph,
          question: `基于以下分析链结果，综合解读异常并给出诊断结论：\n${finalAnswer.answer}`,
          chatHistory: request.chatHistory,
          onTrace: emit ? (text) => emit.thought(text) : undefined,
          tools: deps.createAgentTools(graph.spec.caseId, request.question)
        });
        answer = {
          ...finalAnswer,
          answer: `${finalAnswer.answer}\n\n---\n### 综合解读\n${llmAnswer.answer}`,
          thoughts: [...(finalAnswer.thoughts || []), ...(llmAnswer.thoughts || [])],
          evidenceCards: [...(finalAnswer.evidenceCards || []), ...(llmAnswer.evidenceCards || [])],
          suggestedQueries: llmAnswer.suggestedQueries,
          handoffAgent: llmAnswer.handoffAgent
        };
      } catch {
        // LLM 综合失败不影响已有确定性结果。
      }
    }
    const plan = singlePlanFromChain(chainPlan);
    deps.recordPlannerRun(graph.spec.caseId, request.question, plan, durationMs);
    deps.recordAnswerRun(graph.spec.caseId, request.question, plan, "chain_complete", answer, Date.now() - startedAt);
    deps.updateRuntimeStatus(statusPatch(graph, "chain_complete"));
    deps.syncMemoryFromQueryRuns(deps.loadGraph(graph.spec.caseId));
    emit?.event("chain_done", { chainId: chainPlan.chainId, summaries: results.map((result) => ({ stepId: result.stepId, status: result.status })) });
    return { status: "chain_complete", answer };
  }

  async function run(graph: CaseGraph, request: AgentChatRequest) {
    const startedAt = Date.now();
    if (!apiConfig.llm.apiKey) {
      const plan = llmKeyRequiredPlan();
      const answer = llmKeyRequiredAnswer();
      deps.recordAnswerRun(graph.spec.caseId, request.question, plan, "llm_key_required", answer, Date.now() - startedAt);
      deps.updateRuntimeStatus(statusPatch(graph, "llm_key_required", "missing llm api key"));
      return { status: "llm_key_required", answer };
    }
    const bypassResult = await tryLearnedBypass(graph, request, startedAt);
    if (bypassResult) return bypassResult;
    const plannerStartedAt = Date.now();
    const chainPlan = await deps.planChain(graph, request.question, undefined, request.chatHistory);
    const durationMs = Date.now() - plannerStartedAt;
    if (shouldInterviewBeforeExecution(graph, chainPlan)) {
      return executeInterview(graph, request, chainPlan, durationMs, startedAt);
    }
    if (chainPlan.planKind === "chain") return executeChainPlan(graph, request, chainPlan, durationMs, startedAt);
    return executeSingle(graph, request, singlePlanFromChain(chainPlan), durationMs, startedAt);
  }

  async function stream(graph: CaseGraph, request: AgentChatRequest, emit: StreamEmitter) {
    const startedAt = Date.now();
    if (!apiConfig.llm.apiKey) {
      const plan = llmKeyRequiredPlan();
      const answer = llmKeyRequiredAnswer();
      deps.recordAnswerRun(graph.spec.caseId, request.question, plan, "llm_key_required", answer, Date.now() - startedAt);
      deps.updateRuntimeStatus(statusPatch(graph, "llm_key_required", "missing llm api key"));
      emit.thought("未配置 LLM API Key，Agent 分析未启动。");
      emitAnswerInChunks(emit, answer.answer);
      emit.done(answer);
      return;
    }
    const bypassResult = await tryLearnedBypass(graph, request, startedAt, (text) => emit.thought(text));
    if (bypassResult) {
      bypassResult.answer.thoughts?.forEach((thought) => emit.thought(thought));
      emitAnswerInChunks(emit, bypassResult.answer.answer);
      emit.done(bypassResult.answer);
      return;
    }
    const plannerStartedAt = Date.now();
    const chainPlan = await deps.planChain(graph, request.question, (text) => emit.thought(text), request.chatHistory);
    const durationMs = Date.now() - plannerStartedAt;
    const stepSummary = chainPlan.steps.map((step) => `${step.intent}(${step.purpose})`).join(" → ");
    emit.thought(`规划完成：${chainPlan.planKind}（${chainPlan.confidence}）${stepSummary}${chainPlan.reason ? `，${chainPlan.reason}` : ""}`);
    if (shouldInterviewBeforeExecution(graph, chainPlan)) {
      emit.thought("上下文不足，先进入诊断访谈，不执行宽查询。");
      const result = executeInterview(graph, request, chainPlan, durationMs, startedAt);
      emitAnswerInChunks(emit, result.answer.answer);
      emit.done(result.answer);
      return;
    }
    if (chainPlan.planKind === "chain") {
      const result = await executeChainPlan(graph, request, chainPlan, durationMs, startedAt, emit);
      emit.delta(result.answer.answer);
      emit.done(result.answer);
      return;
    }
    const result = await executeSingle(graph, request, singlePlanFromChain(chainPlan), durationMs, startedAt, (text) => emit.thought(text));
    result.answer.thoughts?.forEach((thought) => emit.thought(thought));
    emitAnswerInChunks(emit, result.answer.answer);
    emit.done(result.answer);
  }

  return { run, stream };
}
