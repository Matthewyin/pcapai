import type { AgentAnswer, CaseGraph } from "../../../../packages/shared/src/index.js";
import { runPcapTroubleshootingAgent } from "../agents/runtime.js";
import { runProtocolAdapter, type ProtocolAdapter } from "../protocolAdapters/types.js";

type PlannedResult = { status: string; answer: AgentAnswer } | null;

type LearnedPattern = { regex: RegExp; adapterId: string };

type ProtocolEventQueryServiceInput = {
  adapters: ProtocolAdapter[];
  hasLlmApiKey: () => boolean;
  loadLearnedPatterns: () => LearnedPattern[];
  learnFromAgentRun: (question: string, toolCalls: string[], adapterIds: string[]) => void;
  incrementHitCount: (adapterId: string, regexSource: string) => void;
};

const protocolHints: Record<string, RegExp> = {
  dns: /\bdns\b|解析|域名|nxdomain|servfail/i,
  tcp: /\btcp\b|重传|rst|zero.?window|握手|syn/i,
  tls: /\btls\b|ssl|证书|cipher|handshake/i,
  icmp: /\bicmp\b|unreachable|ttl|fragment/i,
  udp: /\budp\b|quic/i,
  http: /\bhttp\b|状态码|status.?code/i
};

function prioritizeAdapters(adapters: ProtocolAdapter[], question: string) {
  if (adapters.length <= 1) return adapters;
  const prioritized = adapters.filter((adapter) => {
    const hint = protocolHints[adapter.id];
    return hint && hint.test(question);
  });
  return prioritized.length ? prioritized : adapters;
}

function combineProtocolAnswers(results: Array<{ adapter: ProtocolAdapter; answer: AgentAnswer }>): AgentAnswer {
  return {
    answer: results.map((result) => result.answer.answer).join("\n\n---\n\n"),
    thoughts: results.flatMap((result) => result.answer.thoughts || []),
    evidenceCards: results.flatMap((result) => result.answer.evidenceCards || []),
    actions: results.flatMap((result) => result.answer.actions || []),
    evidenceIds: results.flatMap((result) => result.answer.evidenceIds),
    packetIds: results.flatMap((result) => result.answer.packetIds),
    sessionLinkIds: results.flatMap((result) => result.answer.sessionLinkIds),
    findingIds: results.flatMap((result) => result.answer.findingIds),
    missingContext: results.flatMap((result) => result.answer.missingContext),
    confidence: results.every((result) => result.answer.confidence === "certain")
      ? "certain"
      : results.some((result) => !result.answer.confidence || result.answer.confidence === "low" || result.answer.confidence === "needs_context")
        ? "low"
        : "high",
    suggestedActions: results.flatMap((result) => result.answer.suggestedActions),
    suggestedQueries: results.flatMap((result) => result.answer.suggestedQueries || []),
    handoffAgent: results[results.length - 1]?.answer.handoffAgent
  };
}

export function createProtocolEventQueryService(input: ProtocolEventQueryServiceInput) {
  function adapterIds() {
    return input.adapters.map((adapter) => adapter.id);
  }

  async function run(graph: CaseGraph, question: string): Promise<PlannedResult> {
    const matching = prioritizeAdapters(input.adapters.filter((adapter) => adapter.match(question)), question);
    if (!matching.length) {
      const adapterResult = await runProtocolAdapter(input.adapters, graph, question, input.loadLearnedPatterns());
      if (adapterResult) {
        // 命中自学习模式时标注来源并累计命中次数，便于发现错误路由和评估模式质量
        if (adapterResult.matchSource === "learned" && adapterResult.learnedRegex) {
          input.incrementHitCount(adapterResult.adapter.id, adapterResult.learnedRegex);
          adapterResult.answer.thoughts = [
            `命中自学习模式（regex: ${adapterResult.learnedRegex}），路由到 ${adapterResult.adapter.id}。如路由有误，可通过 DELETE /api/settings/learned-patterns 删除该模式。`,
            ...(adapterResult.answer.thoughts || [])
          ];
        }
        return { status: adapterResult.adapter.status, answer: adapterResult.answer };
      }
      if (!input.hasLlmApiKey()) return null;
      try {
        const agentAnswer = await runPcapTroubleshootingAgent({ graph, question });
        input.learnFromAgentRun(question, agentAnswer.toolCalls || [], adapterIds());
        return { status: "agent_fallback", answer: agentAnswer };
      } catch {
        return null;
      }
    }
    if (matching.length === 1) {
      const answer = await matching[0].run(graph, question);
      return { status: matching[0].status, answer };
    }
    const results = await Promise.all(matching.map(async (adapter) => ({ adapter, answer: await adapter.run(graph, question) })));
    return { status: "deterministic_multi_protocol", answer: combineProtocolAnswers(results) };
  }

  return { run, adapterIds };
}
