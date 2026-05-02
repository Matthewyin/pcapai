import type { PacketSummary } from "../../../../packages/shared/src/index.js";
import { buildProtocolCorrelations } from "./builders.js";
import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListTlsEvents(question: string) {
  return /tls|ssl|https|sni|证书|alert|握手|clienthello|serverhello|server hello|client hello/i.test(question);
}

function tlsEventLabel(packet: PacketSummary) {
  if (packet.tlsAlertDescription !== undefined) return `TLS Alert ${packet.tlsAlertDescription}`;
  if (packet.tlsHandshakeType === 1) return "ClientHello";
  if (packet.tlsHandshakeType === 2) return "ServerHello";
  if (packet.tlsHandshakeType === 11) return "Certificate";
  if (packet.tlsHandshakeType !== undefined) return `TLS handshake ${packet.tlsHandshakeType}`;
  return "TLS packet";
}

function tlsCheck(packets: PacketSummary[]) {
  const clientHelloPackets = packets.filter((packet) => packet.tlsHandshakeType === 1);
  const serverHelloPackets = packets.filter((packet) => packet.tlsHandshakeType === 2);
  const alertPackets = packets.filter((packet) => packet.tlsAlertDescription !== undefined);
  if (alertPackets.length) {
    return {
      status: "problem" as const,
      summary: `发现 ${alertPackets.length} 个 TLS Alert，优先查看首个 Alert 的方向和前后握手包。`,
      packetIds: alertPackets.map((packet) => packet.packetId)
    };
  }
  if (clientHelloPackets.length && !serverHelloPackets.length) {
    return {
      status: "problem" as const,
      summary: "看到 ClientHello，但当前查询范围内未看到 ServerHello，TLS 握手可能未得到服务端响应。",
      packetIds: clientHelloPackets.map((packet) => packet.packetId)
    };
  }
  if (clientHelloPackets.length && serverHelloPackets.length) {
    return {
      status: "ok" as const,
      summary: "当前查询范围内能看到 ClientHello 和 ServerHello。",
      packetIds: [clientHelloPackets[0].packetId, serverHelloPackets[0].packetId]
    };
  }
  return {
    status: packets.length ? "unknown" as const : "ok" as const,
    summary: packets.length ? "发现 TLS 包，但未形成明确握手判断。" : "当前查询范围内没有发现 TLS 包。",
    packetIds: packets.map((packet) => packet.packetId)
  };
}

export function createTlsAdapter(ctx: ProtocolAdapterContext): ProtocolAdapter {
  return {
    id: "tls_events",
    protocol: "tls",
    status: "deterministic_tls",
    errorPrefix: "TLS 查询失败",
    match: shouldListTlsEvents,
    async run(graph, question) {
      const captures = ctx.captureQueryInputs(graph);
      if (!captures.length) return ctx.noCaptureAnswer();
      const limit = ctx.requestedLimit(question, 20);
      const query = await ctx.displayFilterFromQuestion(graph, question, "tls");
      const result = await ctx.listTlsPackets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
      const packets = result.packets.slice(0, limit);
      const queryRunId = `tls-${Date.now()}`;
      const cards = packets.map((packet) => ctx.protocolPacketCard(
        packet,
        queryRunId,
        `${tlsEventLabel(packet)} / Frame ${packet.frameNumber}`,
        `${packet.srcIp || "*"} -> ${packet.dstIp || "*"}，SNI=${packet.tlsSni || "-"}，${packet.summary || "TLS 事件"}`,
        "protocol_event"
      ));
      const protocolCorrelations = buildProtocolCorrelations(queryRunId, "tls", packets, cards);
      const check = tlsCheck(packets);
      return ctx.protocolQueryAnswer({
        graph,
        queryRunId,
        queryInput: query.input,
        displayFilter: query.displayFilter,
        protocol: "tls",
        title: `前 ${limit} 个 TLS 事件`,
        packets,
        noResult: "当前查询范围内没有发现 TLS 事件。",
        thoughts: [
          "识别为 L7 TLS 握手/Alert 查询。",
          `构造 display filter：${query.displayFilter}`,
          "调用 tshark-query MCP 查询 TLS 包，并提取握手类型、SNI 和 Alert。",
          "将 TLS SNI 关联回承载它的 TCP flow。"
        ],
        evidenceCards: cards,
        protocolCorrelations,
        checks: [{
          key: "tls",
          label: "TLS 握手",
          status: check.status,
          summary: `${check.summary}${protocolCorrelations.length ? ` 已生成 ${protocolCorrelations.length} 条 TLS-to-TCP 关联。` : ""}`,
          packetIds: check.packetIds,
          nextSteps: ["查看 ClientHello / ServerHello / Alert 的方向、SNI 和前后 TCP session 状态。"]
        }],
        suggestedActions: ["查看 TLS Alert 方向、SNI、证书阶段和底层 TCP 是否重传或被 RST。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
