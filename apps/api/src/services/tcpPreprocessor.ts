import type { MappingHint, PacketSummary } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";
import { queryPacketsWithMcp } from "../mcp/tsharkQueryClient.js";
import type { CaptureQueryInput } from "../mcp/tsharkQueryClient.js";

function pairKey(packet: PacketSummary) {
  return [`${packet.srcIp || ""}:${packet.srcPort ?? ""}`, `${packet.dstIp || ""}:${packet.dstPort ?? ""}`].sort().join(" <-> ");
}

function dedupPackets(packets: PacketSummary[]): PacketSummary[] {
  const seen = new Set<string>();
  return packets.filter((p) => {
    if (seen.has(p.packetId)) return false;
    seen.add(p.packetId);
    return true;
  });
}

function buildIpFilter(mappingHints?: MappingHint[]): string {
  if (!mappingHints?.length) return "";
  const ips = new Set<string>();
  for (const hint of mappingHints) {
    if (hint.originalSrcIp) ips.add(hint.originalSrcIp);
    if (hint.originalDstIp) ips.add(hint.originalDstIp);
    if (hint.translatedSrcIp) ips.add(hint.translatedSrcIp);
    if (hint.translatedDstIp) ips.add(hint.translatedDstIp);
  }
  if (!ips.size) return "";
  return ` && (${[...ips].map((ip) => `ip.addr == ${ip}`).join(" || ")})`;
}

export type AnomalyExtraction = {
  packets: PacketSummary[];
  truncated: boolean;
  note: string;
};

type CategoryResult = {
  label: string;
  packets: PacketSummary[];
  truncated: boolean;
};

// 多协议异常预提取：TCP 异常 + DNS 失败 + TLS 告警/握手 + HTTP 4xx/5xx + ICMP 异常。
// 洞察引擎的 30 个分析器都读这里产出的 packets，覆盖范围必须如实记录到 insightCoverage。
export async function extractProtocolAnomalies(
  inputs: CaptureQueryInput[],
  mappingHints?: MappingHint[]
): Promise<AnomalyExtraction> {
  const ipFilter = buildIpFilter(mappingHints);
  const limit = apiConfig.preprocess.anomalyPacketLimit;
  const tcpBase = `tcp${ipFilter}`;

  async function category(label: string, displayFilter: string): Promise<CategoryResult> {
    try {
      const result = await queryPacketsWithMcp({ captures: inputs, displayFilter, limit });
      return { label, packets: result.packets, truncated: Boolean(result.truncated) || result.packets.length >= limit };
    } catch {
      return { label, packets: [], truncated: false };
    }
  }

  const [rst, retrans, zeroWin, dupAck, lostSeg, synPackets, dnsFail, tlsEvents, httpErrors, icmpEvents] = await Promise.all([
    category("TCP RST", `${tcpBase} && tcp.flags.reset == 1`),
    category("TCP 重传", `${tcpBase} && (tcp.analysis.retransmission || tcp.analysis.fast_retransmission)`),
    category("TCP Zero Window", `${tcpBase} && tcp.analysis.zero_window`),
    category("TCP 重复 ACK", `${tcpBase} && tcp.analysis.duplicate_ack`),
    category("TCP 丢段", `${tcpBase} && tcp.analysis.lost_segment`),
    category("TCP SYN", `${tcpBase} && tcp.flags.syn == 1`),
    category("DNS 失败响应", `dns.flags.rcode != 0${ipFilter}`),
    category("TLS 告警/握手", `(tls.alert_message || tls.handshake.type)${ipFilter}`),
    category("HTTP 4xx/5xx", `http.response.code >= 400${ipFilter}`),
    category("ICMP 异常", `(icmp.type == 3 || icmp.type == 5 || icmp.type == 11 || icmpv6.type == 1 || icmpv6.type == 3)${ipFilter}`)
  ]);

  const anomalyPackets = dedupPackets([
    ...rst.packets,
    ...retrans.packets,
    ...zeroWin.packets,
    ...dupAck.packets,
    ...lostSeg.packets
  ]);

  // 为有异常的 endpoint pair 补充握手上下文
  const anomalousPairs = new Set(anomalyPackets.map(pairKey));
  const synContext = synPackets.packets.filter((p) => anomalousPairs.has(pairKey(p)));

  // 找出建链失败：有 SYN 无 SYN-ACK 的 pair
  const hasSynAck = new Set<string>();
  for (const p of synPackets.packets) {
    if (p.tcpFlags?.includes("SYN") && p.tcpFlags?.includes("ACK")) {
      hasSynAck.add(pairKey(p));
    }
  }
  const failedSyn = synContext.filter((p) =>
    p.tcpFlags?.includes("SYN") && !p.tcpFlags?.includes("ACK") && !hasSynAck.has(pairKey(p))
  );

  const packets = dedupPackets([
    ...anomalyPackets,
    ...synContext,
    ...failedSyn,
    ...dnsFail.packets,
    ...tlsEvents.packets,
    ...httpErrors.packets,
    ...icmpEvents.packets
  ]);

  const categories = [rst, retrans, zeroWin, dupAck, lostSeg, dnsFail, tlsEvents, httpErrors, icmpEvents];
  const truncatedLabels = categories.filter((c) => c.truncated).map((c) => c.label);
  const countText = categories.filter((c) => c.packets.length).map((c) => `${c.label} ${c.packets.length}`).join("、") || "无异常包";
  const note = [
    `预提取覆盖：TCP 异常（RST/重传/Zero Window/重复 ACK/丢段/建链失败）、DNS 失败响应、TLS 告警与握手、HTTP 4xx/5xx、ICMP 不可达/重定向/TTL 超时；其余协议事件需另行查询。`,
    `各类计数：${countText}。`,
    truncatedLabels.length ? `以下类别达到 ${limit} 条上限被截断，实际数量可能更多：${truncatedLabels.join("、")}。` : ""
  ].filter(Boolean).join(" ");

  return { packets, truncated: truncatedLabels.length > 0, note };
}
