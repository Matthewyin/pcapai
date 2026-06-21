// 单条 TCP 会话的六维健康分类纯函数。
// 从 buildQueryDiagnosis 抽取，让 query-run 深诊断和连接健康全景 adapter 共用同一套判定口径。
// 判定基于包级别（PacketSummary），比会话摘要（rstCount/tcpFlags）更精确。
import type { Conversation, PacketSummary } from "../../../../packages/shared/src/index.js";

export type HealthStatus = "ok" | "warn" | "problem" | "unknown";

export type ConversationHealthInput = {
  // 会话端点（用于判定包方向：forward = 与端点一致，reverse = 反向）
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  // 该会话的全部包
  packets: PacketSummary[];
};

export type ConversationHealth = {
  handshake: HealthStatus;
  rst: HealthStatus;
  trafficDirection: HealthStatus;
  retransmission: HealthStatus;
  zeroWindow: HealthStatus;
  closeState: HealthStatus;
  issues: string[];   // 非正常项的中文标签，如 ["握手未建立", "RST"]
  isNormal: boolean;  // issues 为空
};

export type ConversationHealthThresholds = {
  retransmissionBurst: number; // 重传突发阈值，达到为 problem
};

function hasFlag(packet: PacketSummary, flag: string) {
  return packet.tcpFlags?.includes(flag) ?? false;
}

function packetDirection(packet: PacketSummary, input: ConversationHealthInput): "forward" | "reverse" | "none" {
  const { srcIp, srcPort, dstIp, dstPort } = input;
  const matchesForward = packet.srcIp === srcIp && packet.srcPort === srcPort && packet.dstIp === dstIp && packet.dstPort === dstPort;
  const matchesReverse = packet.srcIp === dstIp && packet.srcPort === dstPort && packet.dstIp === srcIp && packet.dstPort === srcPort;
  if (matchesForward) return "forward";
  if (matchesReverse) return "reverse";
  return "none";
}

export function classifyConversationHealth(
  input: ConversationHealthInput,
  thresholds: ConversationHealthThresholds
): ConversationHealth {
  const { packets } = input;
  const forwardPackets = packets.filter((p) => packetDirection(p, input) === "forward");
  const reversePackets = packets.filter((p) => packetDirection(p, input) === "reverse");

  const synPackets = forwardPackets.filter((p) => hasFlag(p, "SYN") && !hasFlag(p, "ACK"));
  const synAckPackets = reversePackets.filter((p) => hasFlag(p, "SYN") && hasFlag(p, "ACK"));
  const handshakeAckPackets = synAckPackets.length
    ? forwardPackets.filter((p) => p.timestamp >= synAckPackets[0].timestamp && hasFlag(p, "ACK") && !hasFlag(p, "SYN"))
    : [];
  const rstPackets = packets.filter((p) => hasFlag(p, "RST"));
  const retransmissionPackets = packets.filter((p) => p.tcpAnalysis?.retransmission || p.tcpAnalysis?.fastRetransmission);
  const zeroWindowPackets = packets.filter((p) => p.tcpAnalysis?.zeroWindow);
  const forwardFinPackets = forwardPackets.filter((p) => hasFlag(p, "FIN"));
  const reverseFinPackets = reversePackets.filter((p) => hasFlag(p, "FIN"));

  // handshake
  const handshake: HealthStatus = synPackets.length && synAckPackets.length && handshakeAckPackets.length
    ? "ok"
    : synPackets.length && synAckPackets.length
      ? "warn"
      : synPackets.length
        ? "problem"
        : "unknown";

  // rst
  const rst: HealthStatus = rstPackets.length ? "problem" : "ok";

  // traffic direction
  const trafficDirection: HealthStatus = forwardPackets.length && reversePackets.length
    ? "ok"
    : forwardPackets.length || reversePackets.length
      ? "problem"
      : "unknown";

  // retransmission
  const retransmission: HealthStatus = retransmissionPackets.length >= thresholds.retransmissionBurst
    ? "problem"
    : retransmissionPackets.length > 0
      ? "warn"
      : "ok";

  // zero window
  const zeroWindow: HealthStatus = zeroWindowPackets.length ? "problem" : "ok";

  // close state
  const closeState: HealthStatus = rstPackets.length
    ? "warn"
    : forwardFinPackets.length && reverseFinPackets.length
      ? "ok"
      : forwardFinPackets.length || reverseFinPackets.length
        ? "warn"
        : "unknown";

  const issues: string[] = [];
  if (handshake === "problem") issues.push("握手未建立");
  if (rst === "problem") issues.push("RST");
  if (retransmission === "problem") issues.push("重传");
  else if (retransmission === "warn") issues.push("少量重传");
  if (zeroWindow === "problem") issues.push("零窗口");
  if (trafficDirection === "problem") issues.push("单向");

  return { handshake, rst, trafficDirection, retransmission, zeroWindow, closeState, issues, isNormal: issues.length === 0 };
}

// 摘要级六维健康分类：基于 tshark-query MCP 的 summarizeConversations 产出的方向级字段
// （handshakePhase/forwardPacketCount/reversePacketCount/rstCount/retransmissionCount/zeroWindowCount），
// 而非整包列表。判定口径与上面的包级 classifyConversationHealth 对齐，让连接健康全景 adapter
// （只有会话摘要、无逐包）和 query-run 深诊断（有逐包）给出一致结论。
// closeState 在摘要层无法可靠判定（需 FIN 包方向+时序），统一返回 unknown。
export function classifyConversationHealthFromSummary(
  conv: Conversation,
  thresholds: ConversationHealthThresholds
): ConversationHealth {
  // handshake：MCP 已按方向级时序算出 handshakePhase，直接映射。
  const handshake: HealthStatus =
    conv.handshakePhase === "complete" ? "ok"
    : conv.handshakePhase === "syn_ack" ? "warn"
    : conv.handshakePhase === "syn" ? "problem"
    : "unknown";

  const hasRst = conv.rstCount > 0;
  const rst: HealthStatus = hasRst ? "problem" : "ok";

  // traffic direction：与包级判定一致——双向有包即 ok，仅单向即 problem，无包则 unknown。
  const hasForward = conv.forwardPacketCount > 0;
  const hasReverse = conv.reversePacketCount > 0;
  const trafficDirection: HealthStatus = hasForward && hasReverse
    ? "ok"
    : hasForward || hasReverse
      ? "problem"
      : "unknown";

  const retransmission: HealthStatus = conv.retransmissionCount >= thresholds.retransmissionBurst
    ? "problem"
    : conv.retransmissionCount > 0
      ? "warn"
      : "ok";

  const zeroWindow: HealthStatus = conv.zeroWindowCount > 0 ? "problem" : "ok";

  const closeState: HealthStatus = "unknown";

  const issues: string[] = [];
  if (handshake === "problem") issues.push("握手未建立");
  if (rst === "problem") issues.push("RST");
  if (retransmission === "problem") issues.push("重传");
  else if (retransmission === "warn") issues.push("少量重传");
  if (zeroWindow === "problem") issues.push("零窗口");
  if (trafficDirection === "problem") issues.push("单向");

  return { handshake, rst, trafficDirection, retransmission, zeroWindow, closeState, issues, isNormal: issues.length === 0 };
}
