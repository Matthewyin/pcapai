import type { AgentAnswer, CaseGraph, QueryRun, ToolRun } from "../../../../packages/shared/src/index.js";
import type { AgentIntentPlan } from "../agents/runtime.js";

type ToolRunInput = Omit<ToolRun, "toolRunId" | "createdAt" | "evidenceCardIds"> & { evidenceCardIds?: string[] };

export function createToolRunService(input: {
  readGraph: (caseId: string) => CaseGraph;
  writeGraph: (graph: CaseGraph) => void;
  setGraph: (caseId: string, graph: CaseGraph) => void;
}) {
  function recordToolRun(caseId: string, runInput: ToolRunInput) {
    const graph = input.readGraph(caseId);
    const toolRun: ToolRun = {
      toolRunId: `tool-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      ...runInput,
      evidenceCardIds: runInput.evidenceCardIds || []
    };
    const nextGraph: CaseGraph = {
      ...graph,
      toolRuns: [toolRun, ...(graph.toolRuns || [])].slice(0, 100)
    };
    input.writeGraph(nextGraph);
    input.setGraph(caseId, nextGraph);
    return toolRun;
  }

  function recordPlannerRun(caseId: string, question: string, plan: AgentIntentPlan, durationMs: number) {
    return recordToolRun(caseId, {
      kind: "planner",
      status: "success",
      target: "Leader Intent Planner",
      question,
      intent: plan.intent,
      summary: `${plan.intent}（${plan.confidence}）：${plan.reason || "无补充说明"}`,
      durationMs
    });
  }

  function recordAnswerRun(caseId: string, question: string, plan: AgentIntentPlan, status: string, answer: AgentAnswer, durationMs: number) {
    const graph = input.readGraph(caseId);
    const isQueryBacked = status.includes("query") || status.includes("statistics") || status.includes("correlation") || status.includes("protocol");
    return recordToolRun(caseId, {
      kind: isQueryBacked ? "mcp" : "agent",
      status: "success",
      target: status,
      question,
      intent: plan.intent,
      summary: answer.answer.split("\n").find(Boolean)?.slice(0, 300) || status,
      queryRunId: isQueryBacked ? graph.activeQueryRunId : undefined,
      evidenceCardIds: answer.evidenceCards?.map((card) => card.cardId) || [],
      durationMs
    });
  }

  function recordErrorRun(caseId: string, question: string, plan: AgentIntentPlan, status: string, error: unknown, durationMs: number) {
    return recordToolRun(caseId, {
      kind: "tool",
      status: "error",
      target: status,
      question,
      intent: plan.intent,
      summary: "执行失败",
      durationMs,
      error: error instanceof Error ? error.message : String(error)
    });
  }

  function recordMcpRun(caseId: string, runInput: {
    target: string;
    question?: string;
    summary: string;
    inputSummary?: string;
    outputSummary?: string;
    queryRunId?: string;
    evidenceCardIds?: string[];
    pcapFilename?: string;
    frameNumber?: number;
    displayFilter?: string;
    packetDisplayFilter?: string;
    durationMs?: number;
  }) {
    return recordToolRun(caseId, {
      kind: "mcp",
      status: "success",
      ...runInput
    });
  }

  function recordQueryRunMcp(caseId: string, target: string, question: string, queryRun: QueryRun, summary: string, inputSummary: string, outputSummary: string) {
    const actionableCard = queryRun.evidenceCards.find((card) => card.pcapFilename && (card.displayFilter || card.packetDisplayFilter || card.frameNumber))
      || queryRun.evidenceCards.find((card) => card.displayFilter || card.packetDisplayFilter || card.frameNumber);
    return recordMcpRun(caseId, {
      target,
      question,
      summary,
      inputSummary,
      outputSummary,
      queryRunId: queryRun.queryRunId,
      evidenceCardIds: queryRun.evidenceCards.map((card) => card.cardId),
      pcapFilename: actionableCard?.pcapFilename,
      frameNumber: actionableCard?.frameNumber,
      displayFilter: actionableCard?.displayFilter || queryRun.displayFilter,
      packetDisplayFilter: actionableCard?.packetDisplayFilter
    });
  }

  return {
    recordToolRun,
    recordPlannerRun,
    recordAnswerRun,
    recordErrorRun,
    recordMcpRun,
    recordQueryRunMcp
  };
}
