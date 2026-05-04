import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListIcmpEvents(question: string) {
  if (/\bhttp\b|dns|解析|域名|tls|ssl|udp/i.test(question)) return false;
  return /icmp|unreachable|不可达|TTL|ttl|超时|fragmentation|分片|需要分片|端口不可达|主机不可达|网络不可达/i.test(question);
}

function icmpLabel(packet: Parameters<ProtocolAdapterContext["protocolPacketCard"]>[0]) {
  const type = packet.icmpType;
  const code = packet.icmpCode;
  if (type === 3) return `Destination Unreachable${code !== undefined ? ` code ${code}` : ""}`;
  if (type === 11) return "TTL Exceeded";
  if (type === 2) return "Packet Too Big";
  return `ICMP type ${type ?? "?"}${code !== undefined ? ` code ${code}` : ""}`;
}

export function createIcmpAdapter(ctx: ProtocolAdapterContext): ProtocolAdapter {
  return {
    id: "icmp_events",
    protocol: "icmp",
    status: "deterministic_icmp",
    errorPrefix: "ICMP 查询失败",
    match: shouldListIcmpEvents,
    async run(graph, question) {
      const captures = ctx.captureQueryInputs(graph);
      if (!captures.length) return ctx.noCaptureAnswer();
      const displayLimit = ctx.requestedLimit(question, 20);
      const query = await ctx.displayFilterFromQuestion(graph, question, "icmp");
      const result = await ctx.listIcmpEvents({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined });
      const allPackets = result.packets;
      const displayPackets = allPackets.slice(0, displayLimit);
      const queryRunId = `icmp-${Date.now()}`;
      const cards = displayPackets.map((packet) => ctx.protocolPacketCard(
        packet,
        queryRunId,
        `${icmpLabel(packet)} / Frame ${packet.frameNumber}`,
        `${packet.srcIp || "*"} -> ${packet.dstIp || "*"}，${packet.summary || "ICMP 事件"}`,
        "protocol_event"
      ));
      return ctx.protocolQueryAnswer({
        graph,
        queryRunId,
        queryInput: query.input,
        displayFilter: query.displayFilter,
        protocol: "icmp",
        title: allPackets.length > displayLimit ? `共 ${allPackets.length} 个 ICMP 事件（展示前 ${displayLimit} 个）` : `${allPackets.length} 个 ICMP 事件`,
        packets: displayPackets,
        noResult: "当前查询范围内没有发现 ICMP/ICMPv6 事件。",
        thoughts: [
          "识别为 L3 ICMP 事件查询。",
          `构造 display filter：${query.displayFilter}`,
          `tshark 查询返回 ${allPackets.length} 个匹配包。`
        ],
        evidenceCards: cards,
        checks: [{
          key: "icmp",
          label: "ICMP 控制消息",
          status: allPackets.length ? "problem" : "ok",
          summary: allPackets.length ? `发现 ${allPackets.length} 个 ICMP/ICMPv6 事件。` : "未发现 ICMP/ICMPv6 事件。",
          packetIds: displayPackets.map((packet) => packet.packetId),
          nextSteps: ["查看 ICMP 返回源地址和 type/code，判断是哪一跳返回控制消息。"]
        }],
        suggestedActions: ["优先查看 unreachable / TTL exceeded 的源地址，判断是哪一跳返回控制消息。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
