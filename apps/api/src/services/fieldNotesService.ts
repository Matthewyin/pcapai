// 实战知识库（Field Notes）服务：从抓包特征检索已知排障案例。
// v0：纯特征匹配（无飞轮权重、无 question 文本参与、无 FTS5 兜底）。
// 设计见 docs/design-field-notes.md。
//
// 数据流：case graph → extractPacketFeatures（确定性）→ searchFieldNotes（三层打分）→ top K 候选。
// 候选只是提示，Agent 保留否决权，必须用抓包+RFC 验证后才能下结论。
import { existsSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { apiConfig } from "../config.js";
import { buildFtsMatchQuery } from "./rfcCorpus.js";
import type { CaseGraph, PacketSummary } from "../../../../packages/shared/src/index.js";

// ── 数据模型（与 buildFieldNotesIndex.ts 的 schema 对应）──

export type PacketFeatures = {
  observedFlags?: string[];
  missingFlags?: string[];
  analysisFlags?: string[];
  protocols?: string[];
};

export type CandidateCause = {
  cause: string;
  rfcDocId?: number;
  rfcSection?: string;
  likelihood: "high" | "medium" | "low";
  howToVerify: string;
  skillIds?: string[];  // 关联的 Skills（方法论层 SOP），命中后用 get_skill 读取详细步骤
};

export type FieldNote = {
  id: string;
  title: string;
  summary: string;
  protocols: string[];
  symptoms: string[];
  packetFeatures: PacketFeatures;
  candidateCauses: CandidateCause[];
  source: string;
  // 飞轮元数据（P8 沉淀闭环）：用户确认/纠正驱动权重演进
  verifiedCount: number;
  disputedCount: number;
  lastVerifiedAt?: string;
  createdAt: string;
};

export type FieldNoteHit = {
  note: FieldNote;
  featureScore: number; // 特征匹配分（missingFlag×3 + analysisFlag×2 + observedFlag×1）
};

// ── 抓包特征提取（确定性）──
// observedFlags/analysisFlags 从包提取；missingFlags 从 queryRuns 的 conversations 提取（复用 MCP
// 的 handshakePhase，方案 B 成果）。这样 timestamp 种子能靠 missingFlags:["SYN-ACK"] 精确命中。
export function extractPacketFeatures(graph: CaseGraph): PacketFeatures {
  const packets: PacketSummary[] = graph.rawPackets?.length ? graph.rawPackets : graph.packets || [];
  const protocols = new Set<string>();
  const observedFlags = new Set<string>();
  const analysisFlags = new Set<string>();
  for (const packet of packets) {
    if (packet.protocol) protocols.add(packet.protocol.toUpperCase());
    packet.tcpFlags?.forEach((flag) => observedFlags.add(flag));
    if (packet.tcpAnalysis?.retransmission || packet.tcpAnalysis?.fastRetransmission) analysisFlags.add("retransmission");
    if (packet.tcpAnalysis?.zeroWindow) analysisFlags.add("zero_window");
  }
  // missingFlags：遍历所有 queryRun 的 TCP 会话，按 handshakePhase 推断缺失的 flag
  const missingFlags = new Set<string>();
  for (const run of graph.queryRuns || []) {
    for (const conv of run.conversations || []) {
      if (conv.protocol?.toUpperCase() !== "TCP") continue;
      // handshakePhase: "syn" = 发了 SYN 无 SYN-ACK → 缺 SYN-ACK
      if (conv.handshakePhase === "syn") missingFlags.add("SYN-ACK");
    }
  }
  return {
    observedFlags: [...observedFlags],
    analysisFlags: [...analysisFlags],
    missingFlags: [...missingFlags],
    protocols: [...protocols]
  };
}

// ── 检索（三层过滤，v0 纯特征打分）──

let db: Database.Database | null = null;
let openDbPath = "";

function fieldNotesIndexPath(): string {
  return process.env.PCAPAI_FIELD_NOTES_INDEX_PATH
    ? path.resolve(process.env.PCAPAI_FIELD_NOTES_INDEX_PATH)
    : apiConfig.fieldNotes.indexPath;
}

export function resetFieldNotesIndexCache(): void {
  db?.close();
  db = null;
  openDbPath = "";
}

export class FieldNotesIndexMissingError extends Error {
  constructor() {
    super("实战知识库索引未构建。请先在项目根目录运行 npm run fieldnotes:build。");
  }
}

function getDb(): Database.Database {
  const indexPath = fieldNotesIndexPath();
  if (db && openDbPath === indexPath) return db;
  if (db) resetFieldNotesIndexCache();
  if (!existsSync(indexPath)) throw new FieldNotesIndexMissingError();
  // 读写连接：P8 沉淀闭环需要 verify/dispute/createNote 写操作。
  // WAL 模式避免读写互斥，better-sqlite3 同步 API 天然无并发问题。
  db = new Database(indexPath, { fileMustExist: true });
  db.pragma("journal_mode = WAL");
  openDbPath = indexPath;
  return db;
}

type NoteRow = {
  id: string;
  title: string;
  summary: string;
  protocols: string;
  symptoms: string;
  packet_features: string;
  candidate_causes: string;
  source: string;
  verified_count: number;
  disputed_count: number;
  last_verified_at: string | null;
  created_at: string;
};

function rowToNote(row: NoteRow): FieldNote {
  return {
    id: row.id,
    title: row.title,
    summary: row.summary,
    protocols: JSON.parse(row.protocols),
    symptoms: JSON.parse(row.symptoms),
    packetFeatures: JSON.parse(row.packet_features),
    candidateCauses: JSON.parse(row.candidate_causes),
    source: row.source,
    verifiedCount: row.verified_count,
    disputedCount: row.disputed_count,
    lastVerifiedAt: row.last_verified_at || undefined,
    createdAt: row.created_at
  };
}

function scoreNote(note: FieldNote, features: PacketFeatures): number {
  const scores = apiConfig.fieldNotes.scores;
  let score = 0;
  const featMissing = features.missingFlags || [];
  const noteMissing = note.packetFeatures.missingFlags || [];
  if (featMissing.length && noteMissing.length) {
    for (const flag of noteMissing) {
      if (featMissing.includes(flag)) score += scores.missingFlag;
    }
  }
  const featAnalysis = features.analysisFlags || [];
  const noteAnalysis = note.packetFeatures.analysisFlags || [];
  if (featAnalysis.length && noteAnalysis.length) {
    for (const flag of noteAnalysis) {
      if (featAnalysis.includes(flag)) score += scores.analysisFlag;
    }
  }
  const featObserved = features.observedFlags || [];
  const noteObserved = note.packetFeatures.observedFlags || [];
  if (featObserved.length && noteObserved.length) {
    for (const flag of noteObserved) {
      if (featObserved.includes(flag)) score += scores.observedFlag;
    }
  }
  return score;
}

export function searchFieldNotes(features: PacketFeatures, topK = apiConfig.fieldNotes.topK, question?: string): FieldNoteHit[] {
  const database = getDb();
  const rows = database.prepare(
    "SELECT id, title, summary, protocols, symptoms, packet_features, candidate_causes, source, verified_count, disputed_count, last_verified_at, created_at FROM notes"
  ).all() as NoteRow[];

  const featProtocols = new Set((features.protocols || []).map((p) => p.toUpperCase()));
  const hits: FieldNoteHit[] = [];
  for (const row of rows) {
    const note = rowToNote(row);
    // 第 1 层：协议过滤（任一协议交集即可，宽松召回）
    const noteProtocols = new Set(note.protocols.map((p) => p.toUpperCase()));
    const protocolOverlap = featProtocols.size === 0 || noteProtocols.size === 0
      ? true
      : [...featProtocols].some((p) => noteProtocols.has(p));
    if (!protocolOverlap) continue;
    // 第 2 层：特征打分
    const featureScore = scoreNote(note, features);
    if (featureScore <= 0) continue;
    hits.push({ note, featureScore });
  }
  // 排序：飞轮权重——verifiedCount 提权、disputedCount 降权，让经典案例上浮
  hits.sort((left, right) => {
    const leftFinal = left.featureScore * (1 + left.note.verifiedCount * 0.1) / (1 + left.note.disputedCount * 0.5);
    const rightFinal = right.featureScore * (1 + right.note.verifiedCount * 0.1) / (1 + right.note.disputedCount * 0.5);
    return rightFinal - leftFinal || left.note.id.localeCompare(right.note.id);
  });

  // FTS5 兜底：特征分全 0（hits 为空）且 question 含英文关键词时，走全文检索
  if (!hits.length && question) {
    const match = buildFtsMatchQuery(question);
    if (match) {
      const ftsRows = database.prepare(`
        SELECT n.id, n.title, n.summary, n.protocols, n.symptoms, n.packet_features, n.candidate_causes, n.source,
               n.verified_count, n.disputed_count, n.last_verified_at, n.created_at,
               bm25(notes_fts) AS score
        FROM notes_fts
        JOIN notes n ON n.rowid = notes_fts.rowid
        WHERE notes_fts MATCH ?
        ORDER BY score
        LIMIT ?
      `).all(match.or, topK) as (NoteRow & { score: number })[];
      for (const row of ftsRows) {
        hits.push({ note: rowToNote(row), featureScore: 0 });
      }
    }
  }

  return hits.slice(0, topK);
}

// 索引状态查询（供调试 / 健康检查用）
export function fieldNotesIndexStatus(): { built: boolean; noteCount?: number; indexPath: string } {
  const indexPath = fieldNotesIndexPath();
  if (!existsSync(indexPath)) {
    return { built: false, indexPath };
  }
  const database = getDb();
  const row = database.prepare("SELECT COUNT(*) AS count FROM notes").get() as { count: number };
  return { built: true, noteCount: row.count, indexPath };
}

// ── P8 沉淀闭环：写操作（verify / dispute / create / list / get）──

// 列出全部笔记（管理用）
export function listAllFieldNotes(): FieldNote[] {
  const database = getDb();
  const rows = database.prepare(
    "SELECT id, title, summary, protocols, symptoms, packet_features, candidate_causes, source, verified_count, disputed_count, last_verified_at, created_at FROM notes ORDER BY created_at"
  ).all() as NoteRow[];
  return rows.map(rowToNote);
}

// 单条笔记
export function getFieldNote(id: string): FieldNote | null {
  const database = getDb();
  const row = database.prepare(
    "SELECT id, title, summary, protocols, symptoms, packet_features, candidate_causes, source, verified_count, disputed_count, last_verified_at, created_at FROM notes WHERE id = ?"
  ).get(id) as NoteRow | undefined;
  return row ? rowToNote(row) : null;
}

// 用户确认结论正确 → verifiedCount++，更新 lastVerifiedAt
export function verifyFieldNote(id: string): { updated: boolean; note: FieldNote | null } {
  const database = getDb();
  const existing = getFieldNote(id);
  if (!existing) return { updated: false, note: null };
  database.prepare(
    "UPDATE notes SET verified_count = verified_count + 1, last_verified_at = ? WHERE id = ?"
  ).run(new Date().toISOString(), id);
  return { updated: true, note: getFieldNote(id) };
}

// 用户纠正 → disputedCount++；可选 correction 写入 userNotes（暂存纠正内容，供后续审核）
export function disputeFieldNote(id: string, correction?: string): { updated: boolean; note: FieldNote | null } {
  const database = getDb();
  const existing = getFieldNote(id);
  if (!existing) return { updated: false, note: null };
  database.prepare(
    "UPDATE notes SET disputed_count = disputed_count + 1 WHERE id = ?"
  ).run(id);
  // correction 暂存到 summary 末尾（v1 简化：未来加独立 corrections 表）
  if (correction?.trim()) {
    database.prepare("UPDATE notes SET summary = summary || ? WHERE id = ?").run(`\n[用户纠正] ${correction.trim()}`, id);
  }
  return { updated: true, note: getFieldNote(id) };
}

// 新增笔记（手动/管理员/Agent 沉淀）
export function createFieldNote(input: Omit<FieldNote, "createdAt" | "verifiedCount" | "disputedCount"> & { verifiedCount?: number; disputedCount?: number }): { created: boolean; note: FieldNote | null; reason?: string } {
  const database = getDb();
  if (getFieldNote(input.id)) {
    return { created: false, note: null, reason: `笔记已存在：${input.id}（更新请用 update）` };
  }
  const now = new Date().toISOString();
  database.prepare(
    `INSERT INTO notes(id, title, summary, protocols, symptoms, packet_features, candidate_causes, source, verified_count, disputed_count, last_verified_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`
  ).run(
    input.id,
    input.title,
    input.summary,
    JSON.stringify(input.protocols),
    JSON.stringify(input.symptoms || []),
    JSON.stringify(input.packetFeatures),
    JSON.stringify(input.candidateCauses),
    input.source || "user",
    input.verifiedCount ?? 0,
    input.disputedCount ?? 0,
    now
  );
  return { created: true, note: getFieldNote(input.id) };
}

// 删除笔记（管理/测试清理用）。不存在视为已删除（幂等）。
export function deleteFieldNote(id: string): { deleted: boolean } {
  const database = getDb();
  database.prepare("DELETE FROM notes WHERE id = ?").run(id);
  return { deleted: true };
}
