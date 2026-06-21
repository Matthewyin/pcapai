import assert from "node:assert/strict";
import test from "node:test";
import { existsSync } from "node:fs";
import { apiConfig } from "../src/config.js";
import {
  extractPacketFeatures,
  searchFieldNotes,
  fieldNotesIndexStatus,
  listAllFieldNotes,
  getFieldNote,
  verifyFieldNote,
  disputeFieldNote,
  createFieldNote,
  deleteFieldNote,
  type PacketFeatures
} from "../src/services/fieldNotesService.js";
import type { CaseGraph, PacketSummary } from "../../packages/shared/src/index.js";

// ── extractPacketFeatures: 纯函数，不依赖 SQLite ──

function packet(patch: Partial<PacketSummary>): PacketSummary {
  return {
    packetId: "p",
    nodeId: "node-1",
    pcapFilename: "node.pcap",
    frameNumber: 1,
    timestamp: 100,
    protocol: "tcp",
    tcpFlags: [],
    tcpAnalysis: { retransmission: false, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false },
    summary: "",
    raw: {},
    ...patch
  };
}

function minimalGraph(packets: PacketSummary[]): CaseGraph {
  // 只填 extractPacketFeatures 用到的字段
  return { rawPackets: packets } as unknown as CaseGraph;
}

test("extractPacketFeatures: 提取 protocol/observedFlags/analysisFlags", () => {
  const features = extractPacketFeatures(minimalGraph([
    packet({ protocol: "tcp", tcpFlags: ["SYN"] }),
    packet({ protocol: "TCP", tcpFlags: ["SYN", "ACK"], tcpAnalysis: { retransmission: true, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false } }),
    packet({ protocol: "dns", tcpFlags: [] })
  ]));
  assert.ok(features.protocols?.includes("TCP"));
  assert.ok(features.protocols?.includes("DNS"));
  assert.ok(features.observedFlags?.includes("SYN"));
  assert.ok(features.observedFlags?.includes("ACK"));
  assert.ok(features.analysisFlags?.includes("retransmission"));
  // 无 queryRuns 时 missingFlags 为空数组
  assert.deepEqual(features.missingFlags || [], []);
});

test("extractPacketFeatures: 从 conversations 的 handshakePhase 提取 missingFlags", () => {
  // 模拟 SYN 无 SYN-ACK：queryRun 里有一条 TCP 会话 handshakePhase=syn
  const graph = {
    rawPackets: [packet({ protocol: "tcp", tcpFlags: ["SYN"] })],
    queryRuns: [{
      conversations: [{ protocol: "TCP", handshakePhase: "syn" }]
    }]
  } as unknown as CaseGraph;
  const features = extractPacketFeatures(graph);
  assert.ok(features.missingFlags?.includes("SYN-ACK"));
});

test("extractPacketFeatures: handshakePhase=complete 时不产生 missingFlags", () => {
  const graph = {
    rawPackets: [packet({ protocol: "tcp", tcpFlags: ["SYN"] })],
    queryRuns: [{
      conversations: [{ protocol: "TCP", handshakePhase: "complete" }]
    }]
  } as unknown as CaseGraph;
  const features = extractPacketFeatures(graph);
  assert.deepEqual(features.missingFlags || [], []);
});

test("extractPacketFeatures: 空包列表返回空特征", () => {
  const features = extractPacketFeatures(minimalGraph([]));
  assert.deepEqual(features.protocols, []);
  assert.deepEqual(features.observedFlags, []);
});

test("extractPacketFeatures: rawPackets 为空时回退到 packets", () => {
  const graph = { packets: [packet({ protocol: "tcp", tcpFlags: ["RST"] })] } as unknown as CaseGraph;
  const features = extractPacketFeatures(graph);
  assert.ok(features.observedFlags?.includes("RST"));
});

// ── searchFieldNotes: 依赖已构建的 SQLite 库 ──
// 库未构建时 skip（对齐 rfc-corpus.test.ts 不测 searchRfc 的风格）。

const indexReady = existsSync(apiConfig.fieldNotes.indexPath);

// 套件开始前清理上次可能的 test- 前缀残留，保证幂等
if (indexReady) {
  for (const n of listAllFieldNotes().map((n) => n.id).filter((id) => id.startsWith("test-note-"))) {
    deleteFieldNote(n);
  }
}

test("searchFieldNotes: missingFlags SYN-ACK 精确命中 timestamp 种子（高分）", { skip: !indexReady }, () => {
  // 模拟 SYN 无 SYN-ACK：missingFlags:SYN-ACK 精确命中（+3）+ observedFlags:SYN（+1）= 4 分
  const features: PacketFeatures = { observedFlags: ["SYN"], missingFlags: ["SYN-ACK"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features);
  assert.ok(hits.length > 0, "应命中至少一条笔记");
  const timestampHit = hits.find((h) => h.note.id.includes("timestamp"));
  assert.ok(timestampHit, "应命中 timestamp 种子");
  // missingFlag(3) + observedFlag SYN(1) = 4
  assert.equal(timestampHit!.featureScore, 4);
});

test("searchFieldNotes: 仅 observedFlags SYN 弱命中（无 missingFlags）", { skip: !indexReady }, () => {
  // 只有 SYN，没有 missingFlags → 弱命中（1 分）
  const features: PacketFeatures = { observedFlags: ["SYN"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features);
  const timestampHit = hits.find((h) => h.note.id.includes("timestamp"));
  assert.ok(timestampHit, "弱命中也应返回 timestamp 种子");
  assert.equal(timestampHit!.featureScore, 1);
});

test("searchFieldNotes: 特征不命中时 question 英文关键词走 FTS5 兜底", { skip: !indexReady }, () => {
  // 特征完全不匹配（只给 FIN），但 question 含英文关键词能 FTS5 命中
  const features: PacketFeatures = { observedFlags: ["FIN"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features, 3, "TCP timestamp SYN no response");
  // FTS5 兜底命中，featureScore=0
  assert.ok(hits.length > 0, "FTS5 兜底应命中");
  assert.equal(hits[0].featureScore, 0);
});

test("searchFieldNotes: 纯中文 question 不走 FTS5（buildFtsMatchQuery 返回 null）", { skip: !indexReady }, () => {
  const features: PacketFeatures = { observedFlags: ["FIN"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features, 3, "为什么连接建立失败");
  assert.equal(hits.length, 0, "纯中文不触发 FTS5，应返回空");
});

test("searchFieldNotes: retransmission analysisFlag 命中退避种子", { skip: !indexReady }, () => {
  const features: PacketFeatures = {
    observedFlags: ["SYN", "ACK", "PSH"],
    analysisFlags: ["retransmission"],
    protocols: ["TCP"]
  };
  const hits = searchFieldNotes(features);
  const backoffHit = hits.find((h) => h.note.id.includes("backoff"));
  assert.ok(backoffHit, "应命中指数退避种子");
  // analysisFlag=2 + observedFlags(SYN/ACK/PSH)=3 → 总分 5
  assert.ok((backoffHit!.featureScore ?? 0) >= 5);
});

test("searchFieldNotes: 协议不匹配时过滤掉", { skip: !indexReady }, () => {
  const features: PacketFeatures = { observedFlags: ["SYN"], protocols: ["UDP"] };
  const hits = searchFieldNotes(features);
  // UDP 协议过滤掉所有 TCP 种子
  assert.equal(hits.length, 0);
});

test("searchFieldNotes: 无任何特征匹配时返回空", { skip: !indexReady }, () => {
  const features: PacketFeatures = { observedFlags: ["FIN"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features);
  // 种子里没有 FIN observedFlag，得 0 分被过滤
  assert.equal(hits.length, 0);
});

test("searchFieldNotes: topK 截断", { skip: !indexReady }, () => {
  const features: PacketFeatures = { observedFlags: ["SYN", "ACK"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features, 1);
  assert.ok(hits.length <= 1);
});

test("searchFieldNotes: 结果按特征分降序排序", { skip: !indexReady }, () => {
  const features: PacketFeatures = {
    observedFlags: ["SYN", "ACK", "PSH"],
    analysisFlags: ["retransmission"],
    protocols: ["TCP"]
  };
  const hits = searchFieldNotes(features);
  for (let i = 1; i < hits.length; i++) {
    assert.ok(hits[i - 1].featureScore >= hits[i].featureScore, "应按特征分降序");
  }
});

test("fieldNotesIndexStatus: 库存在时返回 noteCount", { skip: !indexReady }, () => {
  const status = fieldNotesIndexStatus();
  assert.equal(status.built, true);
  assert.ok((status.noteCount ?? 0) >= 2);
});

test("searchFieldNotes: 命中笔记的 candidateCause 带 skillIds", { skip: !indexReady }, () => {
  const features: PacketFeatures = { observedFlags: ["SYN"], missingFlags: ["SYN-ACK"], protocols: ["TCP"] };
  const hits = searchFieldNotes(features);
  const timestampHit = hits.find((h) => h.note.id.includes("timestamp"));
  assert.ok(timestampHit);
  const timestampCause = timestampHit!.note.candidateCauses.find((c) => c.cause.includes("timestamp"));
  assert.ok(timestampCause, "应有 timestamp 候选真因");
  assert.ok(timestampCause!.skillIds?.includes("verify-tcp-options"), "应关联 verify-tcp-options skill");
});

// ── P8 沉淀闭环：写操作（verify/dispute/create/list/get）──
// 用 test- 前缀 id 隔离，测完残留可接受（与 skills 测试同风格）

test("createFieldNote + getFieldNote + listAllFieldNotes", { skip: !indexReady }, () => {
  const result = createFieldNote({
    id: "test-note-crud-001",
    title: "测试笔记",
    summary: "用于测试 CRUD",
    protocols: ["TCP"],
    symptoms: ["测试症状"],
    packetFeatures: { observedFlags: ["SYN"], protocols: ["TCP"] },
    candidateCauses: [{ cause: "测试真因", likelihood: "low", howToVerify: "测试方法" }],
    source: "user"
  });
  assert.equal(result.created, true);

  const note = getFieldNote("test-note-crud-001");
  assert.ok(note);
  assert.equal(note!.title, "测试笔记");
  assert.equal(note!.verifiedCount, 0);
  assert.equal(note!.disputedCount, 0);

  const all = listAllFieldNotes();
  assert.ok(all.some((n) => n.id === "test-note-crud-001"));
});

test("createFieldNote: 重复 id 拒绝", { skip: !indexReady }, () => {
  createFieldNote({
    id: "test-note-dup-001",
    title: "原版",
    summary: "x",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: {},
    candidateCauses: [],
    source: "user"
  });
  const dup = createFieldNote({
    id: "test-note-dup-001",
    title: "新版",
    summary: "x",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: {},
    candidateCauses: [],
    source: "user"
  });
  assert.equal(dup.created, false);
  assert.ok(dup.reason?.includes("已存在"));
});

test("verifyFieldNote: verifiedCount++ 并更新 lastVerifiedAt", { skip: !indexReady }, () => {
  createFieldNote({
    id: "test-note-verify-001",
    title: "待验证",
    summary: "x",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: {},
    candidateCauses: [],
    source: "user"
  });
  const before = getFieldNote("test-note-verify-001");
  assert.equal(before!.verifiedCount, 0);
  assert.equal(before!.lastVerifiedAt, undefined);

  const result = verifyFieldNote("test-note-verify-001");
  assert.equal(result.updated, true);
  assert.equal(result.note!.verifiedCount, 1);
  assert.ok(result.note!.lastVerifiedAt);
});

test("verifyFieldNote: 不存在返回 updated=false", { skip: !indexReady }, () => {
  const result = verifyFieldNote("nonexistent-note-999");
  assert.equal(result.updated, false);
  assert.equal(result.note, null);
});

test("disputeFieldNote: disputedCount++ 并追加纠正内容", { skip: !indexReady }, () => {
  createFieldNote({
    id: "test-note-dispute-001",
    title: "待纠正",
    summary: "原描述",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: {},
    candidateCauses: [],
    source: "user"
  });
  const result = disputeFieldNote("test-note-dispute-001", "实际是另一个原因");
  assert.equal(result.updated, true);
  assert.equal(result.note!.disputedCount, 1);
  assert.ok(result.note!.summary.includes("实际是另一个原因"));
  assert.ok(result.note!.summary.includes("用户纠正"));
});

test("getFieldNote: 不存在返回 null", { skip: !indexReady }, () => {
  assert.equal(getFieldNote("nonexistent-xxx"), null);
});

test("searchFieldNotes: verifiedCount 高的笔记排序靠前（飞轮权重）", { skip: !indexReady }, () => {
  // 两条特征相同的笔记，一条 verified 多次，应排前面
  createFieldNote({
    id: "test-note-low-verified",
    title: "低验证",
    summary: "x",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: { observedFlags: ["SYN"], protocols: ["TCP"] },
    candidateCauses: [],
    source: "user",
    verifiedCount: 0
  });
  createFieldNote({
    id: "test-note-high-verified",
    title: "高验证",
    summary: "x",
    protocols: ["TCP"],
    symptoms: [],
    packetFeatures: { observedFlags: ["SYN"], protocols: ["TCP"] },
    candidateCauses: [],
    source: "user",
    verifiedCount: 10
  });
  const hits = searchFieldNotes({ observedFlags: ["SYN"], protocols: ["TCP"] }, 20);
  const highIdx = hits.findIndex((h) => h.note.id === "test-note-high-verified");
  const lowIdx = hits.findIndex((h) => h.note.id === "test-note-low-verified");
  assert.ok(highIdx >= 0 && lowIdx >= 0);
  assert.ok(highIdx < lowIdx, "高 verifiedCount 的笔记应排序靠前");
});

test("清理测试创建的笔记", { skip: !indexReady }, () => {
  for (const note of listAllFieldNotes()) {
    if (note.id.startsWith("test-note-")) deleteFieldNote(note.id);
  }
  const remaining = listAllFieldNotes().filter((n) => n.id.startsWith("test-note-"));
  assert.equal(remaining.length, 0, "应清理所有 test-note- 前缀笔记");
});
