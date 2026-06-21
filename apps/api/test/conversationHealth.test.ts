import assert from "node:assert/strict";
import test from "node:test";
import type { Conversation, PacketSummary } from "../../../packages/shared/src/index.js";
import { classifyConversationHealth, classifyConversationHealthFromSummary } from "../src/services/conversationHealth.js";

const SRC = { srcIp: "1.1.1.2", srcPort: 50000 };
const DST = { dstIp: "2.2.2.1", dstPort: 80 };
const THRESHOLDS = { retransmissionBurst: 3 };

function packet(patch: Partial<PacketSummary> & { srcIp: string; srcPort: number; dstIp: string; dstPort: number; timestamp: number }): PacketSummary {
  return {
    packetId: "p",
    nodeId: "node-1",
    pcapFilename: "node.pcap",
    frameNumber: 1,
    protocol: "tcp",
    tcpFlags: [],
    tcpAnalysis: { retransmission: false, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false },
    summary: "",
    raw: {},
    ...patch
  };
}

// forward 方向包：src→dst
function fwd(flags: string[], timestamp: number, extra?: Partial<PacketSummary>): PacketSummary {
  return packet({ packetId: `f-${timestamp}`, srcIp: SRC.srcIp, srcPort: SRC.srcPort, dstIp: DST.dstIp, dstPort: DST.dstPort, tcpFlags: flags, timestamp, ...extra });
}

// reverse 方向包：dst→src
function rev(flags: string[], timestamp: number, extra?: Partial<PacketSummary>): PacketSummary {
  return packet({ packetId: `r-${timestamp}`, srcIp: DST.dstIp, srcPort: DST.dstPort, dstIp: SRC.srcIp, dstPort: SRC.srcPort, tcpFlags: flags, timestamp, ...extra });
}

test("classifyConversationHealth: 完整三次握手 + 双向数据 + 双侧 FIN → 全部正常", () => {
  const packets = [
    fwd(["SYN"], 100),
    rev(["SYN", "ACK"], 101),
    fwd(["ACK"], 102),
    fwd(["PSH", "ACK"], 103),
    rev(["ACK"], 104),
    fwd(["FIN", "ACK"], 105),
    rev(["FIN", "ACK"], 106)
  ];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.handshake, "ok");
  assert.equal(h.rst, "ok");
  assert.equal(h.trafficDirection, "ok");
  assert.equal(h.retransmission, "ok");
  assert.equal(h.zeroWindow, "ok");
  assert.equal(h.closeState, "ok");
  assert.equal(h.isNormal, true);
  assert.deepEqual(h.issues, []);
});

test("classifyConversationHealth: SYN 无 SYN-ACK → handshake=problem, 握手未建立", () => {
  const packets = [fwd(["SYN"], 100), fwd(["SYN"], 101), fwd(["SYN"], 102)];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.handshake, "problem");
  assert.ok(h.issues.includes("握手未建立"));
  assert.equal(h.isNormal, false);
});

test("classifyConversationHealth: SYN+SYN-ACK 但无第三次 ACK → handshake=warn", () => {
  const packets = [fwd(["SYN"], 100), rev(["SYN", "ACK"], 101)];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.handshake, "warn");
});

test("classifyConversationHealth: 含 RST → rst=problem + closeState=warn", () => {
  const packets = [fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102), rev(["RST"], 103)];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.rst, "problem");
  assert.equal(h.closeState, "warn");
  assert.ok(h.issues.includes("RST"));
});

test("classifyConversationHealth: 单向流量（只有 forward） → trafficDirection=problem", () => {
  const packets = [fwd(["SYN"], 100), fwd(["PSH", "ACK"], 101), fwd(["PSH", "ACK"], 102)];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.trafficDirection, "problem");
  assert.ok(h.issues.includes("单向"));
});

test("classifyConversationHealth: 重传 < 阈值 → retransmission=warn（少量重传）", () => {
  const packets = [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102),
    fwd(["PSH", "ACK"], 103, { tcpAnalysis: { retransmission: true, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false } })
  ];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.retransmission, "warn");
  assert.ok(h.issues.includes("少量重传"));
});

test("classifyConversationHealth: 重传 ≥ 阈值(3) → retransmission=problem", () => {
  const retransAnalysis = { retransmission: true, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false };
  const packets = [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102),
    fwd(["PSH", "ACK"], 103, { tcpAnalysis: retransAnalysis }),
    fwd(["PSH", "ACK"], 104, { tcpAnalysis: retransAnalysis }),
    fwd(["PSH", "ACK"], 105, { tcpAnalysis: retransAnalysis })
  ];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.retransmission, "problem");
  assert.ok(h.issues.includes("重传"));
  assert.ok(!h.issues.includes("少量重传"));
});

test("classifyConversationHealth: 含 Zero Window → zeroWindow=problem", () => {
  const zwAnalysis = { retransmission: false, fastRetransmission: false, duplicateAck: false, zeroWindow: true, lostSegment: false };
  const packets = [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102),
    rev(["ACK"], 103, { tcpAnalysis: zwAnalysis })
  ];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.zeroWindow, "problem");
  assert.ok(h.issues.includes("零窗口"));
});

test("classifyConversationHealth: 单侧 FIN → closeState=warn（非 RST 路径）", () => {
  const packets = [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102),
    fwd(["FIN", "ACK"], 103)
  ];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.closeState, "warn");
  // issues 不含关闭相关（issues 只追踪 5 类异常：handshake/rst/retrans/zeroWindow/trafficDirection）
  assert.ok(!h.issues.some((i) => i.includes("关闭")));
});

test("classifyConversationHealth: 无握手包（中途抓包）→ handshake=unknown", () => {
  const packets = [fwd(["PSH", "ACK"], 100), rev(["ACK"], 101)];
  const h = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  assert.equal(h.handshake, "unknown");
});

// ── 摘要级 classifyConversationHealthFromSummary 测试 ──
// 模拟 tshark-query MCP summarizeConversations 产出的方向级字段，验证摘要级判定与包级口径对齐。

function convSummary(patch: Partial<Conversation>): Conversation {
  return {
    conversationId: "conv-1",
    nodeId: "node-1",
    pcapFilename: "node.pcap",
    protocol: "tcp",
    srcIp: SRC.srcIp,
    srcPort: SRC.srcPort,
    dstIp: DST.dstIp,
    dstPort: DST.dstPort,
    startTime: 100,
    endTime: 200,
    packetCount: 10,
    byteCount: 1000,
    tcpFlags: ["SYN", "ACK"],
    rstCount: 0,
    retransmissionCount: 0,
    zeroWindowCount: 0,
    handshakePhase: "none",
    forwardPacketCount: 0,
    reversePacketCount: 0,
    hasForwardPayload: false,
    hasReversePayload: false,
    rankScore: 0,
    rankReasons: [],
    displayFilter: "tcp",
    ...patch
  };
}

test("classifyConversationHealthFromSummary: handshakePhase complete → handshake=ok", () => {
  const h = classifyConversationHealthFromSummary(convSummary({ handshakePhase: "complete", forwardPacketCount: 5, reversePacketCount: 5 }), THRESHOLDS);
  assert.equal(h.handshake, "ok");
  assert.equal(h.trafficDirection, "ok");
  assert.equal(h.isNormal, true);
});

test("classifyConversationHealthFromSummary: handshakePhase syn_ack → handshake=warn", () => {
  const h = classifyConversationHealthFromSummary(convSummary({ handshakePhase: "syn_ack", forwardPacketCount: 1, reversePacketCount: 1 }), THRESHOLDS);
  assert.equal(h.handshake, "warn");
});

test("classifyConversationHealthFromSummary: handshakePhase syn → handshake=problem（SYN 无 SYN-ACK）", () => {
  const h = classifyConversationHealthFromSummary(convSummary({ handshakePhase: "syn", forwardPacketCount: 3, reversePacketCount: 0 }), THRESHOLDS);
  assert.equal(h.handshake, "problem");
  assert.equal(h.trafficDirection, "problem");
  assert.ok(h.issues.includes("握手未建立"));
  assert.ok(h.issues.includes("单向"));
});

test("classifyConversationHealthFromSummary: handshakePhase none → handshake=unknown（抓包晚于建连）", () => {
  const h = classifyConversationHealthFromSummary(convSummary({ handshakePhase: "none", forwardPacketCount: 5, reversePacketCount: 5 }), THRESHOLDS);
  assert.equal(h.handshake, "unknown");
  // isNormal 只追踪确定性异常（issues），unknown 不计入。三态（normal/undecided/abnormal）
  // 由调用方按"是否存在 unknown 维度"进一步划分，连接健康全景 adapter 正是这么做的。
  assert.equal(h.isNormal, true);
  assert.deepEqual(h.issues, []);
});

test("classifyConversationHealthFromSummary: RST/重传/零窗口 计数映射", () => {
  const h = classifyConversationHealthFromSummary(convSummary({
    handshakePhase: "complete",
    forwardPacketCount: 5, reversePacketCount: 5,
    rstCount: 1, retransmissionCount: 1, zeroWindowCount: 1
  }), THRESHOLDS);
  assert.equal(h.rst, "problem");
  assert.equal(h.retransmission, "warn"); // 1 < 3
  assert.equal(h.zeroWindow, "problem");
  assert.ok(h.issues.includes("RST"));
  assert.ok(h.issues.includes("少量重传"));
  assert.ok(h.issues.includes("零窗口"));
});

test("classifyConversationHealthFromSummary: closeState 恒为 unknown（摘要层无法判定）", () => {
  const h = classifyConversationHealthFromSummary(convSummary({ handshakePhase: "complete", forwardPacketCount: 5, reversePacketCount: 5 }), THRESHOLDS);
  assert.equal(h.closeState, "unknown");
});

// ── 对齐测试：同场景下包级与摘要级结论一致（方案 B 的核心保证） ──
// 给定一组包，先用包级函数判定，再按 MCP 口径手工算出方向级摘要字段，验证两函数在各维度结论一致。
// 这是连接健康全景 adapter 和 query-run 深诊断不再互相矛盾的关键回归点。

function assertAligned(label: string, packets: PacketSummary[], summary: Partial<Conversation>) {
  const packetHealth = classifyConversationHealth({ ...SRC, ...DST, packets }, THRESHOLDS);
  const summaryHealth = classifyConversationHealthFromSummary(convSummary(summary), THRESHOLDS);
  const dims: Array<keyof typeof packetHealth> = ["handshake", "rst", "trafficDirection", "retransmission", "zeroWindow"];
  for (const dim of dims) {
    assert.equal(summaryHealth[dim], packetHealth[dim], `${label}: 维度 ${dim} 不一致 (summary=${summaryHealth[dim]} packet=${packetHealth[dim]})`);
  }
  assert.equal(summaryHealth.isNormal, packetHealth.isNormal, `${label}: isNormal 不一致`);
}

test("对齐: 完整握手 + 双向数据 → 两函数均判定正常", () => {
  assertAligned("完整双向", [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101), fwd(["ACK"], 102),
    fwd(["PSH", "ACK"], 103), rev(["ACK"], 104)
  ], { handshakePhase: "complete", forwardPacketCount: 3, reversePacketCount: 2 });
});

test("对齐: SYN 无 SYN-ACK → 两函数均 handshake=problem 且单向", () => {
  assertAligned("SYN 无响应", [
    fwd(["SYN"], 100), fwd(["SYN"], 101), fwd(["SYN"], 102)
  ], { handshakePhase: "syn", forwardPacketCount: 3, reversePacketCount: 0 });
});

test("对齐: SYN+SYN-ACK 无第三次 ACK → 两函数均 handshake=warn", () => {
  assertAligned("握手不完整", [
    fwd(["SYN"], 100), rev(["SYN", "ACK"], 101)
  ], { handshakePhase: "syn_ack", forwardPacketCount: 1, reversePacketCount: 1 });
});

test("对齐: 纯 forward 单向流（旧摘要逻辑误判重灾区）→ 两函数均 trafficDirection=problem", () => {
  // 旧 classifyConversationBySummary 用去重 tcpFlags 判定，只有 ACK 就判双向 ok（误判）。
  // 方案 B 用 forwardPacketCount/reversePacketCount，与包级判定一致：仅 forward 有包 → problem。
  assertAligned("纯 forward 单向", [
    fwd(["PSH", "ACK"], 100), fwd(["PSH", "ACK"], 101), fwd(["ACK"], 102)
  ], { handshakePhase: "none", forwardPacketCount: 3, reversePacketCount: 0 });
});
