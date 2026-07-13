// SQLite-backed Session：实现 OpenAI Agents SDK 的 Session 接口，把跨轮对话历史持久化到 case 目录。
// SDK 原生 MemorySession 是进程内存（重启丢失），OpenAIConversationsSession 依赖 OpenAI 云端。
// 本实现把历史存到 data/cases/:caseId/session.db，进程重启不丢，case 级隔离。
//
// 设计见 docs/design-full-roadmap.md A6。
// 注：SDK 的 OpenAIResponsesCompactionSession 依赖 OpenAI Responses API 的 responses.compact，
// 第三方模型（MiniMax useResponses=false）不支持，所以原生 compaction 不可用；
// 上下文压缩靠应用层（runtime 侧的摘要 + getItems 的 limit 截断兜底）。
import { mkdirSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import type { AgentInputItem, Session } from "@openai/agents";

type SessionDeps = {
  // session 文件存放目录（通常是 case 目录）。每个 sessionId 一个 db 文件。
  baseDir: string;
  // 稳定标识（用于文件名 + 日志）。不传则自动生成。
  sessionId?: string;
};

// 序列化 / 反序列化：AgentInputItem 是复杂联合类型，整体 JSON 化最稳妥
function serialize(item: AgentInputItem): string {
  return JSON.stringify(item);
}
function deserialize(text: string): AgentInputItem {
  return JSON.parse(text) as AgentInputItem;
}

export class SqliteSession implements Session {
  private readonly sessionId: string;
  private readonly dbPath: string;
  private db: Database.Database;
  private readonly stmtGetAll: Database.Statement;
  private readonly stmtGetRecent: Database.Statement<number>;
  private readonly stmtInsert: Database.Statement;
  private readonly stmtDeleteLast: Database.Statement;
  private readonly stmtCount: Database.Statement;
  private readonly stmtClear: Database.Statement;
  private closed = false;

  constructor(deps: SessionDeps) {
    this.sessionId = deps.sessionId || randomUUID();
    mkdirSync(deps.baseDir, { recursive: true });
    this.dbPath = path.join(deps.baseDir, `session-${this.sanitize(this.sessionId)}.db`);
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = MEMORY");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS items(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL
      );
    `);
    this.stmtGetAll = this.db.prepare("SELECT content FROM items ORDER BY seq");
    this.stmtGetRecent = this.db.prepare("SELECT content FROM items ORDER BY seq DESC LIMIT ?");
    this.stmtInsert = this.db.prepare("INSERT INTO items(content) VALUES (?)");
    this.stmtDeleteLast = this.db.prepare("DELETE FROM items WHERE seq = (SELECT MAX(seq) FROM items)");
    this.stmtCount = this.db.prepare("SELECT COUNT(*) AS n FROM items");
    this.stmtClear = this.db.prepare("DELETE FROM items");
  }

  private sanitize(id: string): string {
    // 防 sessionId 含路径分隔符导致写到 baseDir 之外
    return id.replace(/[^a-zA-Z0-9_-]/g, "_");
  }

  async getSessionId(): Promise<string> {
    return this.sessionId;
  }

  async getItems(limit?: number): Promise<AgentInputItem[]> {
    const rows = limit && limit > 0
      ? (this.stmtGetRecent.all(limit) as Array<{ content: string }>).reverse()
      : (this.stmtGetAll.all() as Array<{ content: string }>);
    return rows.map((row) => deserialize(row.content));
  }

  async addItems(items: AgentInputItem[]): Promise<void> {
    if (!items.length) return;
    const tx = this.db.transaction((batch: AgentInputItem[]) => {
      for (const item of batch) this.stmtInsert.run(serialize(item));
    });
    tx(items);
  }

  async popItem(): Promise<AgentInputItem | undefined> {
    const row = this.stmtGetRecent.get(1) as { content: string } | undefined;
    if (!row) return undefined;
    this.stmtDeleteLast.run();
    return deserialize(row.content);
  }

  async clearSession(): Promise<void> {
    this.stmtClear.run();
  }

  // 供应用层压缩用：返回当前条目数
  itemCount(): number {
    return (this.stmtCount.get() as { n: number }).n;
  }

  // 供应用层压缩用：用摘要替换全部历史（原子操作）
  // 把臃肿的工具输出历史压成少量摘要条目，防 context 爆炸。
  replaceAllWith(summaryItems: AgentInputItem[]): void {
    const tx = this.db.transaction((batch: AgentInputItem[]) => {
      this.stmtClear.run();
      for (const item of batch) this.stmtInsert.run(serialize(item));
    });
    tx(summaryItems);
  }

  close(): void {
    if (this.closed) return;
    this.db.close();
    this.closed = true;
  }
}
