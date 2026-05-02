import type { AgentAnswer, CaseGraph } from "../../../../packages/shared/src/index.js";
import { runIntentPlanner, type AgentIntentPlan } from "../agents/runtime.js";

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
  activeCorrelationNeedsContext: (graph: CaseGraph) => boolean;
  shouldCorrelateCaptures: (question: string) => boolean;
  shouldCreateQueryRun: (question: string) => boolean;
  usageHelpAnswer: () => AgentAnswer;
  deterministicStatisticsAnswer: (graph: CaseGraph, question: string) => Promise<AgentAnswer | null>;
  applyCorrelationContextAndRerun: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  createCaptureCorrelationQueryRun: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  runProtocolEventQuery: (graph: CaseGraph, question: string) => Promise<PlannedResult>;
  createTcpSessionQueryRun: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  selectedSessionProblemAnswer: (graph: CaseGraph) => AgentAnswer;
  activeQueryRunAnswer: (graph: CaseGraph, question: string) => AgentAnswer;
  reportAnswer: (graph: CaseGraph) => AgentAnswer;
  troubleshootingScopeAnswer: () => AgentAnswer;
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

  async function planUserIntent(graph: CaseGraph, question: string, onTrace?: (message: string) => void) {
    if (!input.hasLlmApiKey()) {
      const plan = fallbackIntentPlan(graph, question);
      const fallbackPlan = { ...plan, reason: `未配置 LLM API Key，使用本地兜底意图计划。${plan.reason}` };
      onTrace?.(`${fallbackPlan.reason} intent=${fallbackPlan.intent}。`);
      return fallbackPlan;
    }
    try {
      return await runIntentPlanner({ graph, question, onTrace });
    } catch (error) {
      const plan = fallbackIntentPlan(graph, question);
      const fallbackPlan = { ...plan, reason: `Leader Intent Planner 调用失败，切换到本地兜底计划：${error instanceof Error ? error.message : String(error)}。${plan.reason}` };
      onTrace?.(`${fallbackPlan.reason} intent=${fallbackPlan.intent}。`);
      return fallbackPlan;
    }
  }

  async function executeAgentIntentPlan(graph: CaseGraph, question: string, plan: AgentIntentPlan): Promise<PlannedResult> {
    switch (plan.intent) {
      case "usage_help":
        return { status: "usage_help", answer: input.usageHelpAnswer() };
      case "protocol_statistics":
      case "network_statistics": {
        const answer = await input.deterministicStatisticsAnswer(graph, question);
        return answer ? { status: "deterministic_statistics", answer } : null;
      }
      case "mapping_hint_update":
        if (!input.activeCorrelationNeedsContext(graph)) return null;
        return { status: "correlation_context_applied", answer: await input.applyCorrelationContextAndRerun(graph, question) };
      case "capture_correlation":
        return { status: "capture_correlation", answer: await input.createCaptureCorrelationQueryRun(graph, question) };
      case "protocol_event_query":
        return input.runProtocolEventQuery(graph, question);
      case "tcp_session_query":
        return { status: "query_run", answer: await input.createTcpSessionQueryRun(graph, question) };
      case "selected_session_diagnosis":
        return graph.queryRuns.length ? { status: "selected_session_diagnosis", answer: input.selectedSessionProblemAnswer(graph) } : null;
      case "active_query_explain":
        return graph.queryRuns.length ? { status: "query_run_diagnosis", answer: input.activeQueryRunAnswer(graph, question) } : null;
      case "report_request":
        return { status: "report", answer: input.reportAnswer(graph) };
      case "needs_clarification":
        return { status: "needs_query_scope", answer: input.troubleshootingScopeAnswer() };
      case "llm_explain":
        return null;
      default:
        return null;
    }
  }

  return {
    shouldAnswerUsageHelp: matchesUsageHelp,
    shouldAnswerActiveQueryRun: matchesActiveQueryExplain,
    shouldExplainSelectedSessionProblem: matchesSelectedSessionDiagnosis,
    shouldAskForTroubleshootingScope,
    fallbackIntentPlan,
    planUserIntent,
    executeAgentIntentPlan
  };
}
