import type { PacketSummary } from "../../../../packages/shared/src/index.js";
import { buildProtocolCorrelations } from "./builders.js";
import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListTlsEvents(question: string) {
  if (/\bhttp\b|状态码|dns|解析|域名|icmp|udp/i.test(question)) return false;
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

function tlsSniDistribution(packets: PacketSummary[]) {
  const snis = new Map<string, { sni: string; count: number; packetIds: string[] }>();
  for (const packet of packets) {
    if (!packet.tlsSni) continue;
    const current = snis.get(packet.tlsSni);
    if (current) {
      current.count += 1;
      current.packetIds.push(packet.packetId);
    } else {
      snis.set(packet.tlsSni, { sni: packet.tlsSni, count: 1, packetIds: [packet.packetId] });
    }
  }
  return [...snis.values()].sort((a, b) => b.count - a.count);
}

function tlsVersionSummary(packets: PacketSummary[]) {
  const versions = new Set<string>();
  for (const packet of packets) {
    if (packet.tlsRecordVersion) versions.add(packet.tlsRecordVersion);
    if (packet.tlsHandshakeVersion) versions.add(packet.tlsHandshakeVersion);
  }
  return [...versions];
}

function buildTlsChecks(packets: PacketSummary[], correlations: unknown[]) {
  const checks: Array<{ key: "tls"; label: string; status: "ok" | "warn" | "problem" | "unknown"; summary: string; packetIds: string[]; nextSteps: string[] }> = [];

  const mainCheck = tlsCheck(packets);
  checks.push({
    key: "tls",
    label: "TLS 握手",
    status: mainCheck.status,
    summary: `${mainCheck.summary}${correlations.length ? ` 已生成 ${correlations.length} 条 TLS-to-TCP 关联。` : ""}`,
    packetIds: mainCheck.packetIds,
    nextSteps: ["查看 ClientHello / ServerHello / Alert 的方向、SNI 和前后 TCP session 状态。"]
  });

  const sniDist = tlsSniDistribution(packets);
  if (sniDist.length > 0) {
    checks.push({
      key: "tls",
      label: "TLS SNI 分布",
      status: "ok",
      summary: `${sniDist.length} 个 SNI：${sniDist.slice(0, 5).map((s) => `${s.sni}(${s.count})`).join("、")}。`,
      packetIds: [],
      nextSteps: []
    });
  }

  const versions = tlsVersionSummary(packets);
  if (versions.length > 1) {
    checks.push({
      key: "tls",
      label: "TLS 版本",
      status: "warn",
      summary: `发现多个 TLS 版本：${versions.join("、")}。混合版本可能表明协商降级或不一致配置。`,
      packetIds: [],
      nextSteps: ["确认 TLS 版本协商是否与预期一致。"]
    });
  } else if (versions.length === 1) {
    checks.push({
      key: "tls",
      label: "TLS 版本",
      status: "ok",
      summary: `TLS 版本：${versions[0]}。`,
      packetIds: [],
      nextSteps: []
    });
  }

  const clientHellos = packets.filter((p) => p.tlsHandshakeType === 1);
  const serverHellos = packets.filter((p) => p.tlsHandshakeType === 2);
  if (clientHellos.length > serverHellos.length && serverHellos.length > 0) {
    checks.push({
      key: "tls",
      label: "TLS 握手完整性",
      status: "warn",
      summary: `${clientHellos.length} 个 ClientHello 但只有 ${serverHellos.length} 个 ServerHello。部分握手可能被中断。`,
      packetIds: clientHellos.slice(0, 3).map((p) => p.packetId),
      nextSteps: ["检查被中断的 ClientHello 是否重试成功，以及底层 TCP 是否有 RST。"]
    });
  }

  return checks;
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
      const checks = buildTlsChecks(packets, protocolCorrelations);
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
        checks,
        suggestedActions: ["查看 TLS Alert 方向、SNI、证书阶段和底层 TCP 是否重传或被 RST。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
