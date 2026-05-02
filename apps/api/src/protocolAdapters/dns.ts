import type { PacketSummary } from "../../../../packages/shared/src/index.js";
import { buildProtocolCorrelations } from "./builders.js";
import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListDnsFailures(question: string) {
  return /dns|解析|域名|nxdomain|servfail|rcode|无响应|no response/i.test(question);
}

function dnsTransactionKey(packet: PacketSummary) {
  const endpoints = [packet.srcIp || "", packet.dstIp || ""].sort().join("<->");
  return [packet.nodeId, packet.pcapFilename, packet.dnsId || "", packet.dnsQueryName || "", endpoints].join("|");
}

export function createDnsAdapter(ctx: ProtocolAdapterContext): ProtocolAdapter {
  return {
    id: "dns_failures",
    protocol: "dns",
    status: "deterministic_dns",
    errorPrefix: "DNS 查询失败",
    match: shouldListDnsFailures,
    async run(graph, question) {
      const captures = ctx.captureQueryInputs(graph);
      if (!captures.length) return ctx.noCaptureAnswer();
      const limit = ctx.requestedLimit(question, 20);
      const query = await ctx.displayFilterFromQuestion(graph, question, "dns");
      const result = await ctx.listDnsPackets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
      const groups = new Map<string, PacketSummary[]>();
      for (const packet of result.packets) groups.set(dnsTransactionKey(packet), [...(groups.get(dnsTransactionKey(packet)) || []), packet]);
      const suspicious = [...groups.values()].filter((packets) => {
        const responses = packets.filter((packet) => packet.dnsIsResponse);
        return !responses.length || responses.some((packet) => packet.dnsRcode !== undefined && packet.dnsRcode !== 0);
      }).slice(0, limit);
      const evidencePackets = suspicious.map((packets) => packets.find((packet) => packet.dnsIsResponse) || packets[0]);
      const queryRunId = `dns-${Date.now()}`;
      const cards = evidencePackets.map((packet) => ctx.protocolPacketCard(
        packet,
        queryRunId,
        `${packet.dnsQueryName || "DNS transaction"} / Frame ${packet.frameNumber}`,
        packet.dnsIsResponse ? `DNS 响应 rcode=${packet.dnsRcode ?? "-"}，${packet.summary}` : `DNS 查询未在样本内看到响应，${packet.summary}`,
        "transaction"
      ));
      const protocolCorrelations = buildProtocolCorrelations(queryRunId, "dns", evidencePackets, cards);
      return ctx.protocolQueryAnswer({
        graph,
        queryRunId,
        queryInput: query.input,
        displayFilter: query.displayFilter,
        protocol: "dns",
        title: `前 ${limit} 个 DNS 可疑 transaction`,
        packets: evidencePackets,
        noResult: "当前查询范围内没有发现 DNS 失败或无响应 transaction。",
        thoughts: [
          "识别为 L7 DNS 解析问题查询。",
          `构造 display filter：${query.displayFilter}`,
          "调用 tshark-query MCP 查询 DNS 包，并按 dns.id / qname 聚合。",
          "将 DNS response address 关联为后续 TCP 访问过滤器。"
        ],
        evidenceCards: cards,
        protocolCorrelations,
        checks: [{
          key: "dns",
          label: "DNS 解析结果",
          status: cards.length ? "problem" : "ok",
          summary: cards.length ? `发现 ${cards.length} 个 DNS 失败或无响应 transaction，生成 ${protocolCorrelations.length} 条 DNS-to-TCP 关联。` : "未发现 DNS 失败或无响应 transaction。",
          packetIds: evidencePackets.map((packet) => packet.packetId),
          nextSteps: ["查看 DNS rcode、重试次数和解析结果是否与后续访问目标一致。"]
        }],
        suggestedActions: ["查看 DNS rcode、重试次数和解析结果是否与后续访问目标一致。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
