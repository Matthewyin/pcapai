import assert from "node:assert/strict";
import test from "node:test";
import type { CaseGraph } from "../../../packages/shared/src/index.js";
import { apiConfig } from "../src/config.js";
import { createAgentRuntimeService } from "../src/services/agentRuntimeService.js";

const graph = {
  spec: { caseId: "no-key-case", title: "无 Key 边界", createdAt: new Date().toISOString() },
  captures: [],
  queryRuns: []
} as unknown as CaseGraph;

test("无 LLM Key 时聊天入口明确停止，不调用 Planner、Agent 或确定性执行器", async () => {
  const originalKey = apiConfig.llm.apiKey;
  apiConfig.llm.apiKey = "";
  let forbiddenCalls = 0;
  const forbidden = async () => {
    forbiddenCalls += 1;
    throw new Error("无 Key 时不应调用");
  };
  try {
    const service = createAgentRuntimeService({
      planChain: forbidden,
      executeAgentIntentPlan: forbidden,
      executeChainStep: forbidden,
      loadGraph: () => graph,
      buildAgentQuestion: ({ question }) => question,
      answerWithPlannerThought: (answer) => answer,
      diagnosticInterviewAnswer: () => { throw new Error("无 Key 时不应访谈"); },
      syncMemoryFromQueryRuns: (value) => value,
      recordPlannerRun: () => undefined,
      recordAnswerRun: () => undefined,
      recordErrorRun: () => undefined,
      updateRuntimeStatus: () => undefined,
      adapterIds: () => [],
      createAgentTools: () => [],
      learnFromAgentRun: () => undefined,
      findLearnedBypass: () => null
    });
    const result = await service.run(graph, { question: "分析这个抓包", chatHistory: [] });
    assert.equal(result.status, "llm_key_required");
    assert.equal(result.answer.confidence, "needs_context");
    assert.match(result.answer.answer, /模型配置/);
    assert.equal(forbiddenCalls, 0);
  } finally {
    apiConfig.llm.apiKey = originalKey;
  }
});
