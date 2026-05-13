import assert from "node:assert/strict";
import test from "node:test";
import type { AgentAnswer, CaseGraph, ToolRun } from "../../../packages/shared/src/index.js";
import { createAgentToolRegistryService } from "../src/services/agentToolRegistryService.js";

function graph(overrides: Partial<CaseGraph> = {}): CaseGraph {
  return {
    spec: { caseId: "case-tool", title: "agent-tool-test", protocol: "tcp" },
    captures: [],
    mappingHints: [],
    timeOffsetHints: [],
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [],
    analysisRuns: [],
    toolRuns: [],
    ...overrides
  };
}

function answer(text: string): AgentAnswer {
  return {
    answer: text,
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: [],
    confidence: "certain",
    suggestedActions: []
  };
}

test("createSdkTools records successful local tool calls as ToolRun", async () => {
  const runs: ToolRun[] = [];
  const service = createAgentToolRegistryService({
    usageHelpAnswer: () => answer("使用说明"),
    deterministicStatisticsAnswer: async () => answer("协议统计结果"),
    activeCorrelationNeedsContext: () => false,
    applyCorrelationContextAndRerun: async () => answer("关联上下文已应用"),
    createCaptureCorrelationQueryRun: async () => answer("已关联抓包"),
    runProtocolEventQuery: async () => ({ status: "protocol_event", answer: answer("协议事件") }),
    inferQueryRunInput: () => ({}),
    createQueryRun: async (currentGraph) => currentGraph,
    queryRunAnswer: () => answer("QueryRun 结果"),
    selectedSessionProblemAnswer: () => answer("session 诊断"),
    activeQueryRunAnswer: () => answer("当前查询解释"),
    reportAnswer: () => answer("报告"),
    troubleshootingScopeAnswer: () => answer("需要补充条件"),
    runLlmExplain: async () => answer("LLM 综合解读"),
    loadGraph: () => graph({ activeQueryRunId: "query-1" }),
    recordToolRun: (_caseId, runInput) => {
      runs.push({
        toolRunId: `tool-${runs.length}`,
        createdAt: "2026-01-01T00:00:00.000Z",
        evidenceCardIds: [],
        ...runInput
      });
    }
  });

  const statisticsTool = service.createSdkTools("case-tool", "这个文件中有多少个协议？")
    .find((item) => item.name === "pcapai_get_network_statistics");
  assert.ok(statisticsTool);

  const output = await statisticsTool.invoke(undefined as never, JSON.stringify({ question: "这个文件中有多少个协议？" }), undefined);
  const parsed = JSON.parse(String(output));

  assert.equal(parsed.status, "deterministic_statistics");
  assert.equal(runs.length, 1);
  assert.equal(runs[0].kind, "tool");
  assert.equal(runs[0].status, "success");
  assert.equal(runs[0].target, "pcapai_get_network_statistics");
  assert.equal(runs[0].intent, "network_statistics");
  assert.equal(runs[0].queryRunId, "query-1");
});
