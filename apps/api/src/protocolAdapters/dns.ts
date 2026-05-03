import type { PacketSummary } from "../../../../packages/shared/src/index.js";
import { buildProtocolCorrelations } from "./builders.js";
import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListDnsFailures(question: string) {
  if (/\bhttp\b|状态码|status|[45]xx|tls|ssl|icmp|udp/i.test(question)) return false;
  return /dns|解析|域名|nxdomain|servfail|rcode|无响应|no response/i.test(question);
}

function dnsTransactionKey(packet: PacketSummary) {
  const endpoints = [packet.srcIp || "", packet.dstIp || ""].sort().join("<->");
  return [packet.nodeId, packet.pcapFilename, packet.dnsId || "", packet.dnsQueryName || "", endpoints].join("|");
}

function dnsRcodeDistribution(packets: PacketSummary[]) {
  const distribution = new Map<number, { rcode: number; label: string; count: number; packetIds: string[]; queryNames: string[] }>();
  const rcodeLabels: Record<number, string> = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };
  const responses = packets.filter((p) => p.dnsIsResponse && p.dnsRcode !== undefined);
  for (const packet of responses) {
    const rcode = packet.dnsRcode!;
    const current = distribution.get(rcode);
    if (current) {
      current.count += 1;
      current.packetIds.push(packet.packetId);
      if (packet.dnsQueryName && !current.queryNames.includes(packet.dnsQueryName)) current.queryNames.push(packet.dnsQueryName);
    } else {
      distribution.set(rcode, { rcode, label: rcodeLabels[rcode] || `RCODE${rcode}`, count: 1, packetIds: [packet.packetId], queryNames: packet.dnsQueryName ? [packet.dnsQueryName] : [] });
    }
  }
  return [...distribution.values()].sort((a, b) => b.count - a.count);
}

function dnsUnansweredQueries(packets: PacketSummary[]) {
  const responseIds = new Set(packets.filter((p) => p.dnsIsResponse).map((p) => p.dnsId).filter(Boolean));
  return packets.filter((p) => !p.dnsIsResponse && p.dnsId && !responseIds.has(p.dnsId));
}

function buildDnsChecks(packets: PacketSummary[], evidencePackets: PacketSummary[], correlations: unknown[]) {
  const checks: Array<{ key: "dns"; label: string; status: "ok" | "warn" | "problem" | "unknown"; summary: string; packetIds: string[]; nextSteps: string[] }> = [];

  checks.push({
    key: "dns",
    label: "DNS 解析结果",
    status: evidencePackets.length ? "problem" : "ok",
    summary: evidencePackets.length ? `发现 ${evidencePackets.length} 个 DNS 失败或无响应 transaction，生成 ${correlations.length} 条 DNS-to-TCP 关联。` : "未发现 DNS 失败或无响应 transaction。",
    packetIds: evidencePackets.map((packet) => packet.packetId),
    nextSteps: ["查看 DNS rcode、重试次数和解析结果是否与后续访问目标一致。"]
  });

  const allResponses = packets.filter((p) => p.dnsIsResponse);
  if (allResponses.length) {
    const distribution = dnsRcodeDistribution(packets);
    const errorRcodes = distribution.filter((d) => d.rcode !== 0);
    if (errorRcodes.length) {
      const detail = errorRcodes.map((d) => `${d.label}(${d.count}): ${d.queryNames.slice(0, 3).join(", ")}`).join("；");
      checks.push({
        key: "dns",
        label: "DNS rcode 分布",
        status: "problem",
        summary: `响应码分布：${distribution.map((d) => `${d.label}(${d.count})`).join("、")}。异常：${detail}。`,
        packetIds: errorRcodes.flatMap((d) => d.packetIds.slice(0, 3)),
        nextSteps: ["NXDOMAIN 可能是域名配置错误；SERVFAIL 可能是上游 DNS 故障；REFUSED 可能是 ACL 限制。"]
      });
    } else {
      checks.push({
        key: "dns",
        label: "DNS rcode 分布",
        status: "ok",
        summary: `${distribution.length} 种 rcode：${distribution.map((d) => `${d.label}(${d.count})`).join("、")}。`,
        packetIds: [],
        nextSteps: []
      });
    }
  }

  const unanswered = dnsUnansweredQueries(packets);
  if (unanswered.length) {
    checks.push({
      key: "dns",
      label: "DNS 无响应查询",
      status: "warn",
      summary: `${unanswered.length} 个 DNS 查询未看到响应：${unanswered.slice(0, 5).map((p) => p.dnsQueryName || p.dnsId || "unknown").join("、")}。`,
      packetIds: unanswered.slice(0, 5).map((p) => p.packetId),
      nextSteps: ["检查 DNS 服务器是否可达，是否存在防火墙拦截或 DNS 负载过高。"]
    });
  }

  return checks;
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
      const checks = buildDnsChecks(result.packets, evidencePackets, protocolCorrelations);
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
        checks,
        suggestedActions: ["查看 DNS rcode、重试次数和解析结果是否与后续访问目标一致。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
