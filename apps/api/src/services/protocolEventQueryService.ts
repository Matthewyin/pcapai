import type { Tool } from "@openai/agents";
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
  createCaseGraphTools: (caseId: string) => Tool[];
};

const protocolHints: Record<string, RegExp> = {
  dns: /\bdns\b|解析|域名|nxdomain|servfail/i,
  tcp: /\btcp\b|重传|rst|zero.?window|握手|syn/i,
  tls: /\btls\b|ssl|证书|cipher|handshake/i,
  icmp: /\bicmp\b|unreachable|ttl|fragment/i,
  udp: /\budp\b|quic/i,
  http: /\bhttp\b|状态码|status.?code/i
};

// 链式步骤的结构化参数直接映射到 adapter，不再依赖正则匹配 LLM 生成的 purpose 文本
const protocolAdapterIdMap: Record<string, string> = {
  dns: "dns_failures",
  http: "http_transactions",
  tls: "tls_events",
  udp: "udp_flows",
  icmp: "icmp_events"
};

const tcpEventAdapterIdMap: Record<string, string> = {
  rst: "tcp_rst_pairs",
  reset: "tcp_rst_pairs",
  retransmission: "tcp_retransmission_pairs",
  zero_window: "tcp_zero_window_pairs",
  syn_no_synack: "tcp_syn_no_synack_pairs",
  one_way: "tcp_one_way_pairs",
  overview: "tcp_issues_overview"
};

function adapterIdFromParams(params?: Record<string, unknown>): string | undefined {
  const protocol = typeof params?.protocol === "string" ? params.protocol.trim().toLowerCase() : "";
  if (!protocol) return undefined;
  if (protocol === "tcp") {
    const eventKind = typeof params?.eventKind === "string" ? params.eventKind.trim().toLowerCase() : "";
    return tcpEventAdapterIdMap[eventKind] || "tcp_issues_overview";
  }
  return protocolAdapterIdMap[protocol];
}

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

export type ProtocolEventQueryOptions = {
  params?: Record<string, unknown>;
  // Agent 工具内部调用时禁用 fallback，防止 agent 工具调用里再起一个 agent 形成嵌套
  allowAgentFallback?: boolean;
};

export function createProtocolEventQueryService(input: ProtocolEventQueryServiceInput) {
  function adapterIds() {
    return input.adapters.map((adapter) => adapter.id);
  }

  async function run(graph: CaseGraph, question: string, options?: ProtocolEventQueryOptions): Promise<PlannedResult> {
    const structuredAdapterId = adapterIdFromParams(options?.params);
    if (structuredAdapterId) {
      const adapter = input.adapters.find((candidate) => candidate.id === structuredAdapterId);
      if (adapter) return { status: adapter.status, answer: await adapter.run(graph, question) };
    }
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
      if (options?.allowAgentFallback === false) return null;
      if (!input.hasLlmApiKey()) return null;
      try {
        const agentAnswer = await runPcapTroubleshootingAgent({ graph, question, tools: input.createCaseGraphTools(graph.spec.caseId) });
        // 只学习有据可依的高置信回答，避免低质量回答固化成错误路由
        if ((agentAnswer.confidence === "high" || agentAnswer.confidence === "certain") && (agentAnswer.evidenceCards?.length || agentAnswer.packetIds.length)) {
          input.learnFromAgentRun(question, agentAnswer.toolCalls || [], adapterIds());
        }
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
