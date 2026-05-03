import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListUdpFlows(question: string) {
  if (/\bhttp\b|dns|解析|域名|tls|ssl|icmp/i.test(question)) return false;
  return /udp/i.test(question) && /flow|流|通信|通讯|无响应|单向|unreachable|不可达|前|top|\d+/.test(question);
}

export function createUdpAdapter(ctx: ProtocolAdapterContext): ProtocolAdapter {
  return {
    id: "udp_flows",
    protocol: "udp",
    status: "deterministic_udp",
    errorPrefix: "UDP 查询失败",
    match: shouldListUdpFlows,
    async run(graph, question) {
      const captures = ctx.captureQueryInputs(graph);
      if (!captures.length) return ctx.noCaptureAnswer();
      const limit = ctx.requestedLimit(question, 20);
      const query = await ctx.displayFilterFromQuestion(graph, question, "udp");
      const result = await ctx.listUdpPackets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
      const pairs = ctx.groupPacketPairs(result.packets, query.displayFilter).slice(0, limit);
      const queryRunId = `udp-${Date.now()}`;
      const cards = pairs.map((pair, index) => ({
        cardId: `udp-flow-${queryRunId}-${index + 1}`,
        kind: "conversation" as const,
        title: `${index + 1}. ${pair.src} <-> ${pair.dst}`,
        summary: `UDP ${pair.count} 个包，时间 ${ctx.formatBeijingTime(pair.firstSeen)} - ${ctx.formatBeijingTime(pair.lastSeen)}。`,
        pcapFilename: pair.pcapFilename,
        frameNumber: pair.frameNumber,
        displayFilter: pair.displayFilter,
        packetDisplayFilter: pair.packetDisplayFilter,
        actions: ["open_wireshark", "copy_filter"] as Array<"open_wireshark" | "copy_filter">
      }));
      return ctx.protocolQueryAnswer({
        graph,
        queryRunId,
        queryInput: query.input,
        displayFilter: query.displayFilter,
        protocol: "udp",
        title: `前 ${limit} 个 UDP flow`,
        packets: result.packets,
        noResult: "当前查询范围内没有发现 UDP flow。",
        thoughts: [
          "识别为 L4 UDP flow 查询。",
          `构造 display filter：${query.displayFilter}`,
          "调用 tshark-query MCP 查询 UDP 包，并按 endpoint pair 聚合。"
        ],
        evidenceCards: cards,
        checks: [{
          key: "udp",
          label: "UDP flow 聚合",
          status: cards.length ? "unknown" : "ok",
          summary: cards.length ? `发现 ${cards.length} 个 UDP flow；UDP 是否异常需要结合响应方向和 ICMP unreachable 判断。` : "未发现 UDP flow。",
          packetIds: pairs.flatMap((pair) => pair.packetIds.slice(0, 5)),
          nextSteps: ["结合 ICMP unreachable 和应用协议响应判断 UDP 是否无响应。"]
        }],
        suggestedActions: ["结合 ICMP unreachable 和应用协议响应判断 UDP 是否无响应。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
