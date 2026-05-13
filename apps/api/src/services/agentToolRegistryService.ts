import { z } from "zod";
import { tool, type Tool } from "@openai/agents";
import { QueryRunInputSchema, type AgentAnswer, type CaseGraph, type ToolRun } from "../../../../packages/shared/src/index.js";
import type { AgentIntentPlan } from "../agents/runtime.js";

type PlannedResult = { status: string; answer: AgentAnswer } | null;
type AgentToolIntent = AgentIntentPlan["intent"];
type ToolRunInput = Omit<ToolRun, "toolRunId" | "createdAt" | "evidenceCardIds"> & { evidenceCardIds?: string[] };

type AgentToolRegistryInput = {
  usageHelpAnswer: () => AgentAnswer;
  deterministicStatisticsAnswer: (graph: CaseGraph, question: string) => Promise<AgentAnswer | null>;
  activeCorrelationNeedsContext: (graph: CaseGraph) => boolean;
  applyCorrelationContextAndRerun: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  createCaptureCorrelationQueryRun: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  runProtocolEventQuery: (graph: CaseGraph, question: string) => Promise<PlannedResult>;
  inferQueryRunInput: (question: string, graph: CaseGraph) => unknown;
  createQueryRun: (graph: CaseGraph, input: z.infer<typeof QueryRunInputSchema>) => Promise<CaseGraph>;
  queryRunAnswer: (graph: CaseGraph, queryRunId: string) => AgentAnswer;
  selectedSessionProblemAnswer: (graph: CaseGraph) => AgentAnswer;
  activeQueryRunAnswer: (graph: CaseGraph, question: string) => AgentAnswer;
  reportAnswer: (graph: CaseGraph) => AgentAnswer;
  troubleshootingScopeAnswer: () => AgentAnswer;
  runLlmExplain: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
  loadGraph: (caseId: string) => CaseGraph;
  recordToolRun: (caseId: string, runInput: ToolRunInput) => unknown;
};

export type AgentToolDescriptor = {
  name: string;
  intent: AgentToolIntent;
  description: string;
};

export function createAgentToolRegistryService(input: AgentToolRegistryInput) {
  const tools: AgentToolDescriptor[] = [
    { name: "pcapai_usage_help", intent: "usage_help", description: "返回 pcapAI 使用方法。" },
    { name: "pcapai_get_network_statistics", intent: "network_statistics", description: "查询协议、IP、端口、RST、重传等确定性统计。" },
    { name: "pcapai_list_protocols", intent: "protocol_statistics", description: "统计当前抓包文件中的协议种类和分布。" },
    { name: "pcapai_apply_mapping_hint", intent: "mapping_hint_update", description: "写入 NAT/F5/时间同步等上下文并重跑关联。" },
    { name: "pcapai_correlate_captures", intent: "capture_correlation", description: "对多个抓包文件做跨节点关联。" },
    { name: "pcapai_query_protocol_events", intent: "protocol_event_query", description: "查询 TCP/DNS/TLS/HTTP/ICMP/UDP 协议事件。" },
    { name: "pcapai_create_query_run", intent: "tcp_session_query", description: "按用户条件创建 QueryRun 和候选访问链路。" },
    { name: "pcapai_diagnose_selected_session", intent: "selected_session_diagnosis", description: "诊断当前选中的 TCP session。" },
    { name: "pcapai_explain_active_query", intent: "active_query_explain", description: "解释当前 QueryRun 的证据链。" },
    { name: "pcapai_export_report", intent: "report_request", description: "基于当前证据生成报告。" },
    { name: "pcapai_ask_clarification", intent: "needs_clarification", description: "缺少排障条件时追问上下文。" },
    { name: "pcapai_llm_explain", intent: "llm_explain", description: "调用 Leader Agent 做综合解读。" }
  ];

  async function createTcpSessionQueryRun(graph: CaseGraph, question: string) {
    const queryInput = QueryRunInputSchema.parse({ ...(input.inferQueryRunInput(question, graph) as object), question });
    const nextGraph = await input.createQueryRun(graph, queryInput);
    return input.queryRunAnswer(nextGraph, nextGraph.activeQueryRunId || "");
  }

  function descriptorForIntent(intent: AgentToolIntent) {
    return tools.find((candidate) => candidate.intent === intent);
  }

  async function runIntent(graph: CaseGraph, question: string, intent: AgentToolIntent): Promise<PlannedResult> {
    switch (intent) {
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
        return { status: "query_run", answer: await createTcpSessionQueryRun(graph, question) };
      case "selected_session_diagnosis":
        return graph.queryRuns.length ? { status: "selected_session_diagnosis", answer: input.selectedSessionProblemAnswer(graph) } : null;
      case "active_query_explain":
        return graph.queryRuns.length ? { status: "query_run_diagnosis", answer: input.activeQueryRunAnswer(graph, question) } : null;
      case "report_request":
        return { status: "report", answer: input.reportAnswer(graph) };
      case "needs_clarification":
        return { status: "needs_query_scope", answer: input.troubleshootingScopeAnswer() };
      case "llm_explain":
        return { status: "llm_explain", answer: await input.runLlmExplain(graph, question) };
      default:
        return null;
    }
  }

  async function execute(graph: CaseGraph, question: string, intent: AgentToolIntent): Promise<PlannedResult> {
    const descriptor = descriptorForIntent(intent);
    const startedAt = Date.now();
    try {
      const result = await runIntent(graph, question, intent);
      if (!result) {
        input.recordToolRun(graph.spec.caseId, {
          kind: "tool",
          status: "skipped",
          target: descriptor?.name || intent,
          question,
          intent,
          summary: "工具没有返回结果，需要补充条件或改用其他工具。",
          durationMs: Date.now() - startedAt
        });
        return null;
      }
      const latestGraph = input.loadGraph(graph.spec.caseId);
      input.recordToolRun(graph.spec.caseId, {
        kind: "tool",
        status: "success",
        target: descriptor?.name || intent,
        question,
        intent,
        summary: result.answer.answer.split("\n").find(Boolean)?.slice(0, 300) || result.status,
        outputSummary: result.status,
        queryRunId: latestGraph.activeQueryRunId,
        evidenceCardIds: result.answer.evidenceCards?.map((card) => card.cardId) || [],
        durationMs: Date.now() - startedAt
      });
      return result;
    } catch (error) {
      input.recordToolRun(graph.spec.caseId, {
        kind: "tool",
        status: "error",
        target: descriptor?.name || intent,
        question,
        intent,
        summary: "本地工具执行失败",
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  function createSdkTools(caseId: string, defaultQuestion: string): Tool[] {
    return tools
      .filter((descriptor) => descriptor.intent !== "llm_explain")
      .map((descriptor) => tool({
        name: descriptor.name,
        description: descriptor.description,
        parameters: z.object({
          question: z.string().optional()
        }),
        execute: async ({ question }) => {
          const toolQuestion = question?.trim() || defaultQuestion || descriptor.description;
          const graph = input.loadGraph(caseId);
          const result = await execute(graph, toolQuestion, descriptor.intent);
          if (!result) return JSON.stringify({ status: "no_result", message: "工具没有返回结果，需要补充条件或改用其他工具。" });
          return JSON.stringify({ status: result.status, answer: result.answer });
        }
      }));
  }

  return { tools, execute, createSdkTools };
}
