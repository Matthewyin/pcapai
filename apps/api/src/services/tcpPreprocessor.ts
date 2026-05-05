import type { MappingHint, PacketSummary } from "../../../../packages/shared/src/index.js";
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

export async function extractTcpAnomalies(
  inputs: CaptureQueryInput[],
  mappingHints?: MappingHint[]
): Promise<PacketSummary[]> {
  const ipFilter = buildIpFilter(mappingHints);
  const base = `tcp${ipFilter}`;

  const [rst, retrans, zeroWin, dupAck, lostSeg, synPackets] = await Promise.all([
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && tcp.flags.reset == 1` }).catch(() => ({ packets: [] as PacketSummary[] })),
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && (tcp.analysis.retransmission || tcp.analysis.fast_retransmission)` }).catch(() => ({ packets: [] as PacketSummary[] })),
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && tcp.analysis.zero_window` }).catch(() => ({ packets: [] as PacketSummary[] })),
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && tcp.analysis.duplicate_ack` }).catch(() => ({ packets: [] as PacketSummary[] })),
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && tcp.analysis.lost_segment` }).catch(() => ({ packets: [] as PacketSummary[] })),
    queryPacketsWithMcp({ captures: inputs, displayFilter: `${base} && tcp.flags.syn == 1` }).catch(() => ({ packets: [] as PacketSummary[] }))
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

  return dedupPackets([...anomalyPackets, ...synContext, ...failedSyn]);
}
