// 实战知识库索引构建：读 data/field-notes/seeds/*.json → SQLite。
// 用法：npm run fieldnotes:build
// 设计见 docs/design-field-notes.md。运行时只读 SQLite，不回查 JSON。
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { apiConfig } from "../src/config.js";
import type { FieldNote } from "../src/services/fieldNotesService.js";

const seedsDir = apiConfig.fieldNotes.seedsDir;
const indexPath = apiConfig.fieldNotes.indexPath;

if (!existsSync(seedsDir)) {
  console.error(`未找到种子目录 ${seedsDir}，请确认 api.fieldNotes.seedsDir 配置。`);
  process.exit(1);
}

const seedFiles = readdirSync(seedsDir).filter((file) => file.endsWith(".json"));
if (!seedFiles.length) {
  console.error(`种子目录 ${seedsDir} 下没有 .json 文件。`);
  process.exit(1);
}

const notes: FieldNote[] = [];
for (const file of seedFiles) {
  const filePath = path.join(seedsDir, file);
  try {
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as FieldNote;
    // 基本校验：v0 必填字段
    if (!raw.id || !raw.title || !raw.protocols || !raw.packetFeatures || !raw.candidateCauses) {
      console.warn(`跳过 ${file}：缺少必填字段（id/title/protocols/packetFeatures/candidateCauses）。`);
      continue;
    }
    notes.push({ ...raw, createdAt: raw.createdAt || new Date().toISOString() });
  } catch (error) {
    console.warn(`解析失败 ${file}：${error instanceof Error ? error.message : String(error)}`);
  }
}

if (!notes.length) {
  console.error("没有有效的种子笔记，终止构建。");
  process.exit(1);
}

mkdirSync(path.dirname(indexPath), { recursive: true });
for (const suffix of ["", "-wal", "-shm"]) rmSync(`${indexPath}${suffix}`, { force: true });

const db = new Database(indexPath);
db.pragma("journal_mode = MEMORY");
db.pragma("synchronous = OFF");
db.exec(`
  CREATE TABLE notes(
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    protocols TEXT NOT NULL,
    symptoms TEXT NOT NULL,
    packet_features TEXT NOT NULL,
    candidate_causes TEXT NOT NULL,
    source TEXT NOT NULL,
    verified_count INTEGER NOT NULL DEFAULT 0,
    disputed_count INTEGER NOT NULL DEFAULT 0,
    last_verified_at TEXT,
    created_at TEXT NOT NULL
  );
  -- FTS5 兜底检索：特征分=0 时用 question 关键词走这里（RFC 语料都是英文，symptoms 用中英混合）
  CREATE VIRTUAL TABLE notes_fts USING fts5(search_text, content='notes', content_rowid='rowid');
`);

const insert = db.prepare(
  "INSERT INTO notes(id, title, summary, protocols, symptoms, packet_features, candidate_causes, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
);

const startedAt = Date.now();
db.transaction(() => {
  for (const note of notes) {
    insert.run(
      note.id,
      note.title,
      note.summary,
      JSON.stringify(note.protocols),
      JSON.stringify(note.symptoms || []),
      JSON.stringify(note.packetFeatures),
      JSON.stringify(note.candidateCauses),
      note.source || "seed",
      note.createdAt
    );
  }
})();

// FTS5 search_text = title + summary + symptoms（中英混合，供 question 关键词兜底检索）
db.exec(`
  INSERT INTO notes_fts(rowid, search_text)
  SELECT rowid, title || ' ' || summary || ' ' || symptoms FROM notes
`);
db.exec("INSERT INTO notes_fts(notes_fts) VALUES('optimize')");

db.pragma("journal_mode = DELETE");
db.close();

const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
console.log(`完成：${notes.length} 条实战笔记，耗时 ${seconds}s。`);
console.log(`索引位置：${indexPath}`);
