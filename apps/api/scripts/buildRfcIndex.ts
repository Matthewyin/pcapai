// RFC 全文索引构建：rfc-index.txt 元数据 + 逐篇 txt 章节切分 → SQLite FTS5。
// 用法：npm run rag:build [-- --limit 50] [-- --only 9293] [-- --only-file path] [-- --output path]
//   --limit N        只构建前 N 篇
//   --only DOCID     只构建单篇（调试用）
//   --only-file PATH 按文件中的 RFC 编号列表构建（双层库精简层，如 data/rfc-curated.txt）
//   --output PATH    输出 db 路径（默认 apiConfig.rag.indexPath，精简库用 --output data/rfc-index/rfc-mini.db）
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { apiConfig } from "../src/config.js";
import { parseRfcIndex, parseRfcSections } from "../src/services/rfcCorpus.js";

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const limit = Number(argValue("--limit")) || 0;
const only = Number(argValue("--only")) || 0;
const onlyFile = argValue("--only-file");
const outputPath = argValue("--output") || apiConfig.rag.indexPath;

// 从 only-file 读取 RFC 编号列表（每行一个数字或 "# 注释"）
let onlyDocIds: Set<number> | null = null;
if (onlyFile) {
  if (!existsSync(onlyFile)) {
    console.error(`未找到 --only-file 指定的文件：${onlyFile}`);
    process.exit(1);
  }
  const raw = readFileSync(onlyFile, "utf8");
  onlyDocIds = new Set(
    raw
      .split(/\r?\n/)
      .map((line) => line.split(/[#\s]/)[0]) // 取行首数字（# 前的部分）
      .map((token) => Number(token))
      .filter((num) => Number.isFinite(num) && num > 0)
  );
  console.log(`从 ${onlyFile} 读取 ${onlyDocIds.size} 个 RFC 编号。`);
}

const rfcDir = apiConfig.rag.rfcDir;
const indexPath = outputPath;
const indexFile = path.join(rfcDir, "rfc-index.txt");
if (!existsSync(indexFile)) {
  console.error(`未找到 ${indexFile}，请确认 RFC 目录配置（api.rag.rfcDir）。`);
  process.exit(1);
}

console.log(`解析 ${indexFile} ...`);
let entries = parseRfcIndex(readFileSync(indexFile, "utf8"));
console.log(`索引条目 ${entries.length} 条。`);
if (only) entries = entries.filter((entry) => entry.docId === only);
if (onlyDocIds) {
  entries = entries.filter((entry) => onlyDocIds!.has(entry.docId));
  console.log(`按 --only-file 过滤后剩余 ${entries.length} 篇。`);
}
if (limit) entries = entries.slice(0, limit);

mkdirSync(path.dirname(indexPath), { recursive: true });
for (const suffix of ["", "-wal", "-shm"]) rmSync(`${indexPath}${suffix}`, { force: true });

const db = new Database(indexPath);
db.pragma("journal_mode = MEMORY");
db.pragma("synchronous = OFF");
db.exec(`
  CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE docs(
    doc_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    obsoleted_by TEXT NOT NULL,
    updated_by TEXT NOT NULL
  );
  CREATE TABLE sections(
    id INTEGER PRIMARY KEY,
    doc_id INTEGER NOT NULL,
    section TEXT NOT NULL,
    section_title TEXT NOT NULL,
    body TEXT NOT NULL
  );
  CREATE INDEX idx_sections_doc ON sections(doc_id, section);
  CREATE VIRTUAL TABLE sections_fts USING fts5(body, section_title, content='sections', content_rowid='id');
`);

const insertDoc = db.prepare("INSERT INTO docs(doc_id, title, status, obsoleted_by, updated_by) VALUES (?, ?, ?, ?, ?)");
const insertSection = db.prepare("INSERT INTO sections(doc_id, section, section_title, body) VALUES (?, ?, ?, ?)");

const startedAt = Date.now();
let docCount = 0;
let sectionCount = 0;
let missingCount = 0;

const batchSize = 200;
for (let offset = 0; offset < entries.length; offset += batchSize) {
  const batch = entries.slice(offset, offset + batchSize);
  db.transaction(() => {
    for (const entry of batch) {
      const filePath = path.join(rfcDir, `rfc${entry.docId}.txt`);
      if (!existsSync(filePath)) {
        missingCount += 1;
        continue;
      }
      let sections;
      try {
        sections = parseRfcSections(readFileSync(filePath, "utf8"));
      } catch (error) {
        console.warn(`解析失败 rfc${entry.docId}: ${error instanceof Error ? error.message : String(error)}`);
        continue;
      }
      insertDoc.run(entry.docId, entry.title, entry.status, JSON.stringify(entry.obsoletedBy), JSON.stringify(entry.updatedBy));
      for (const section of sections) {
        insertSection.run(entry.docId, section.section, section.sectionTitle, section.body);
        sectionCount += 1;
      }
      docCount += 1;
    }
  })();
  if ((offset + batchSize) % 1000 < batchSize) {
    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(0);
    console.log(`进度 ${Math.min(offset + batchSize, entries.length)}/${entries.length} 篇，${sectionCount} 节，${elapsed}s`);
  }
}

console.log("构建 FTS5 索引 ...");
db.exec("INSERT INTO sections_fts(rowid, body, section_title) SELECT id, body, section_title FROM sections");
db.exec("INSERT INTO sections_fts(sections_fts) VALUES('optimize')");
db.prepare("INSERT INTO meta(key, value) VALUES('builtAt', ?), ('docCount', ?), ('sectionCount', ?)")
  .run(new Date().toISOString(), String(docCount), String(sectionCount));
db.pragma("journal_mode = DELETE");
db.close();

const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
console.log(`完成：${docCount} 篇 RFC、${sectionCount} 个章节，缺失文件 ${missingCount} 个，耗时 ${seconds}s。`);
console.log(`索引位置：${indexPath}`);
