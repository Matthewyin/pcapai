import { existsSync, statSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { apiConfig } from "../config.js";
import { buildFtsMatchQuery } from "./rfcCorpus.js";

export type RfcSearchHit = {
  docId: number;
  title: string;
  status: string;
  obsoletedBy: number[];
  section: string;
  sectionTitle: string;
  snippet: string;
  score: number;
};

export type RfcSectionResult = {
  docId: number;
  title: string;
  status: string;
  obsoletedBy: number[];
  updatedBy: number[];
  section?: string;
  sectionTitle?: string;
  body?: string;
  truncated?: boolean;
  sections?: Array<{ section: string; sectionTitle: string }>;
};

type DocRow = { doc_id: number; title: string; status: string; obsoleted_by: string; updated_by: string };

/**
 * 双层库加载状态：记录当前用的是哪一层 db。
 * 阶段 3a 双层库：完整库（userData 静默下载，750MB）优先 → 精简库（Resources 内置，20MB）降级。
 */
export type RfcTier = "full" | "curated" | "none";

let db: Database.Database | null = null;
let activeTier: RfcTier = "none";

export function activeRfcTier(): RfcTier {
  return activeTier;
}

export function resetRfcIndexCache(): void {
  db?.close();
  db = null;
  activeTier = "none";
}

export class RfcIndexMissingError extends Error {
  constructor() {
    super(
      "RFC 全文索引未构建。请先在项目根目录运行 npm run rag:build，或等待完整库静默下载完成。"
    );
  }
}

/**
 * 双层库解析：优先完整库（apiConfig.rag.indexPath）→ 降级精简库（apiConfig.rag.curatedIndexPath）。
 * 完整库缺失时静默切到精简库；两者都缺失才抛 RfcIndexMissingError。
 */
function getDb(): Database.Database {
  if (db) return db;
  // 第一层：完整库（开发环境是 data/rfc-index/rfc.db；Mac app 是 userData/rfc.db 静默下载产物）
  if (existsSync(apiConfig.rag.indexPath)) {
    db = new Database(apiConfig.rag.indexPath, { readonly: true, fileMustExist: true });
    activeTier = "full";
    return db;
  }
  // 第二层：精简库（Resources 内置，~118 篇高频 RFC）
  if (existsSync(apiConfig.rag.curatedIndexPath)) {
    db = new Database(apiConfig.rag.curatedIndexPath, { readonly: true, fileMustExist: true });
    activeTier = "curated";
    return db;
  }
  throw new RfcIndexMissingError();
}

function numbersFromJson(value: string): number[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(Number).filter(Number.isFinite) : [];
  } catch {
    return [];
  }
}

export function searchRfc(query: string, topK = apiConfig.rag.topK): RfcSearchHit[] {
  const match = buildFtsMatchQuery(query);
  if (!match) {
    throw new Error("检索词中没有可用的英文关键词；RFC 原文为英文，请用英文关键词（协议名、字段名、行为描述）重试。");
  }
  const database = getDb();
  const statement = database.prepare(`
    SELECT s.doc_id, s.section, s.section_title,
           d.title, d.status, d.obsoleted_by,
           bm25(sections_fts) AS score,
           snippet(sections_fts, 0, '«', '»', ' … ', 28) AS snippet
    FROM sections_fts
    JOIN sections s ON s.id = sections_fts.rowid
    JOIN docs d ON d.doc_id = s.doc_id
    WHERE sections_fts MATCH ?
    ORDER BY score
    LIMIT ?
  `);
  type Row = { doc_id: number; section: string; section_title: string; title: string; status: string; obsoleted_by: string; score: number; snippet: string };
  let rows = statement.all(match.and, topK * 5) as Row[];
  if (!rows.length && match.or !== match.and) rows = statement.all(match.or, topK * 5) as Row[];

  // bm25 分数越小越优；HISTORIC/已废弃文档加罚向劣移动，并在结果中保留废弃标注
  const reranked = rows.map((row) => {
    const obsoletedBy = numbersFromJson(row.obsoleted_by);
    const penalized = row.status === "HISTORIC" || obsoletedBy.length > 0;
    return {
      docId: row.doc_id,
      title: row.title,
      status: row.status,
      obsoletedBy,
      section: row.section,
      sectionTitle: row.section_title,
      snippet: row.snippet.replace(/\s+/g, " ").trim(),
      score: penalized ? row.score + Math.abs(row.score) * 0.4 : row.score
    };
  }).sort((left, right) => left.score - right.score);

  // 同一篇 RFC 最多保留 2 个章节，避免单篇刷屏
  const perDoc = new Map<number, number>();
  const hits: RfcSearchHit[] = [];
  for (const hit of reranked) {
    const count = perDoc.get(hit.docId) || 0;
    if (count >= 2) continue;
    perDoc.set(hit.docId, count + 1);
    hits.push(hit);
    if (hits.length >= topK) break;
  }
  return hits;
}

export function getRfcSection(docId: number, section?: string): RfcSectionResult {
  const database = getDb();
  const doc = database.prepare("SELECT * FROM docs WHERE doc_id = ?").get(docId) as DocRow | undefined;
  if (!doc) throw new Error(`索引中没有 RFC ${docId}；可能编号有误或该 RFC 仅有 PDF 版本。`);
  const base = {
    docId: doc.doc_id,
    title: doc.title,
    status: doc.status,
    obsoletedBy: numbersFromJson(doc.obsoleted_by),
    updatedBy: numbersFromJson(doc.updated_by)
  };
  if (!section) {
    const sections = database.prepare("SELECT section, section_title FROM sections WHERE doc_id = ? ORDER BY id").all(docId) as Array<{ section: string; section_title: string }>;
    return { ...base, sections: sections.map((row) => ({ section: row.section, sectionTitle: row.section_title })) };
  }
  const normalized = section.replace(/^§\s*/, "").replace(/\.$/, "").trim();
  // 精确命中优先；否则把该前缀下的子章节按顺序拼接（如请求 3.5 返回 3.5 + 3.5.x）
  const rows = database.prepare(
    "SELECT section, section_title, body FROM sections WHERE doc_id = ? AND (section = ? OR section LIKE ? || '.%') ORDER BY id"
  ).all(docId, normalized, normalized) as Array<{ section: string; section_title: string; body: string }>;
  if (!rows.length) throw new Error(`RFC ${docId} 中没有章节 ${normalized}；可先不带 section 调用查看章节列表。`);
  const combined = rows.map((row) => `§${row.section} ${row.section_title}\n${row.body}`).join("\n\n");
  const limitChars = apiConfig.rag.sectionCharLimit;
  const truncated = combined.length > limitChars;
  return {
    ...base,
    section: normalized,
    sectionTitle: rows[0].section_title,
    body: truncated ? combined.slice(0, limitChars) : combined,
    truncated
  };
}

export function rfcIndexStatus() {
  // 双层库状态：优先报告完整库，降级报告精简库
  const fullExists = existsSync(apiConfig.rag.indexPath);
  const curatedExists = existsSync(apiConfig.rag.curatedIndexPath);

  if (!fullExists && !curatedExists) {
    return {
      built: false,
      tier: "none" as const,
      indexPath: apiConfig.rag.indexPath,
      curatedIndexPath: apiConfig.rag.curatedIndexPath
    };
  }

  // 优先用完整库报告；否则用精简库
  const reportPath = fullExists ? apiConfig.rag.indexPath : apiConfig.rag.curatedIndexPath;
  const tier = fullExists ? ("full" as const) : ("curated" as const);
  const database = new Database(reportPath, { readonly: true });
  const meta = Object.fromEntries(
    (database.prepare("SELECT key, value FROM meta").all() as Array<{ key: string; value: string }>).map((row) => [row.key, row.value])
  );
  database.close();
  // 陈旧检测：RFC 官方索引文件比构建时间新说明语料已更新，提示重建
  const rfcIndexFile = path.join(apiConfig.rag.rfcDir, "rfc-index.txt");
  const builtAtMs = Date.parse(meta.builtAt || "") || 0;
  const stale = existsSync(rfcIndexFile) && statSync(rfcIndexFile).mtimeMs > builtAtMs;
  return {
    built: true,
    tier,
    stale,
    ...(stale ? { staleNote: "RFC 语料比索引新，请重新运行 npm run rag:build。" } : {}),
    indexPath: apiConfig.rag.indexPath,
    curatedIndexPath: apiConfig.rag.curatedIndexPath,
    activePath: reportPath,
    sizeBytes: statSync(reportPath).size,
    builtAt: meta.builtAt,
    docCount: Number(meta.docCount || 0),
    sectionCount: Number(meta.sectionCount || 0)
  };
}
