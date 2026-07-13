import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import {
  cancelDownload,
  getDownloadStatus,
  rfcDownloadTestHooks,
  startDownload
} from "../src/services/rfcDownloadService.js";

function createValidRfcDb(filePath: string): Buffer {
  const database = new Database(filePath);
  database.exec(`
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE docs(doc_id INTEGER PRIMARY KEY, title TEXT, status TEXT, obsoleted_by TEXT, updated_by TEXT);
    CREATE TABLE sections(id INTEGER PRIMARY KEY, doc_id INTEGER, section TEXT, section_title TEXT, body TEXT);
    CREATE VIRTUAL TABLE sections_fts USING fts5(body, section_title, content='sections', content_rowid='id');
    INSERT INTO docs VALUES(793, 'Transmission Control Protocol', 'INTERNET STANDARD', '[]', '[]');
    INSERT INTO sections(doc_id, section, section_title, body) VALUES(793, '3.4', 'Establishing a connection', 'SYN text');
    INSERT INTO sections_fts(rowid, body, section_title) SELECT id, body, section_title FROM sections;
  `);
  database.prepare("INSERT INTO meta(key, value) VALUES('builtAt', ?), ('docCount', '1'), ('sectionCount', '1')")
    .run(new Date().toISOString());
  database.close();
  return readFileSync(filePath);
}

async function withDownloadSandbox(task: (input: { root: string; target: string; validDb: Buffer }) => Promise<void>) {
  const root = mkdtempSync(path.join(tmpdir(), "pcapai-rfc-download-"));
  const target = path.join(root, "rfc.db");
  const validDb = createValidRfcDb(path.join(root, "source.db"));
  const originalFetch = globalThis.fetch;
  process.env.PCAPAI_RAG_INDEX_PATH = target;
  await rfcDownloadTestHooks.reset();
  try {
    await task({ root, target, validDb });
  } finally {
    await rfcDownloadTestHooks.reset();
    globalThis.fetch = originalFetch;
    delete process.env.PCAPAI_RAG_INDEX_PATH;
    rmSync(root, { recursive: true, force: true });
  }
}

test("启动立即返回后台任务，重复启动复用同一任务，校验通过后才安装", async () => {
  await withDownloadSandbox(async ({ target, validDb }) => {
    let fetchCount = 0;
    let release!: () => void;
    globalThis.fetch = async () => {
      fetchCount += 1;
      await new Promise<void>((resolve) => { release = resolve; });
      return new Response(validDb, { status: 200, headers: { "content-length": String(validDb.length) } });
    };

    const first = startDownload();
    const second = startDownload();
    assert.equal(first.state, "downloading");
    assert.equal(second.taskId, first.taskId);
    assert.equal(getDownloadStatus().state, "downloading");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(fetchCount, 1);

    release();
    await rfcDownloadTestHooks.waitForIdle();
    assert.equal(getDownloadStatus().state, "completed");
    assert.deepEqual(readFileSync(target), validDb);
  });
});

test("取消保留 part，下一次启动发送 Range 并续传", async () => {
  await withDownloadSandbox(async ({ target, validDb }) => {
    const splitAt = Math.min(4096, Math.floor(validDb.length / 2));
    const firstChunk = validDb.subarray(0, splitAt);
    globalThis.fetch = async (_url, init) => {
      const signal = init?.signal as AbortSignal;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(firstChunk);
          signal.addEventListener("abort", () => controller.error(new DOMException("aborted", "AbortError")), { once: true });
        }
      });
      return new Response(stream, { status: 200, headers: { "content-length": String(validDb.length) } });
    };

    startDownload();
    for (let index = 0; index < 50 && (!rfcDownloadTestHooks.readPart() || statSync(`${target}.part`).size < splitAt); index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    cancelDownload();
    await rfcDownloadTestHooks.waitForIdle();
    assert.equal(getDownloadStatus().state, "paused");
    assert.equal(statSync(`${target}.part`).size, splitAt);

    let rangeHeader = "";
    globalThis.fetch = async (_url, init) => {
      rangeHeader = String((init?.headers as Record<string, string>)?.Range || "");
      const rest = validDb.subarray(splitAt);
      return new Response(rest, {
        status: 206,
        headers: {
          "content-length": String(rest.length),
          "content-range": `bytes ${splitAt}-${validDb.length - 1}/${validDb.length}`
        }
      });
    };
    startDownload();
    await rfcDownloadTestHooks.waitForIdle();
    assert.equal(rangeHeader, `bytes=${splitAt}-`);
    assert.equal(getDownloadStatus().state, "completed");
    assert.deepEqual(readFileSync(target), validDb);
  });
});

test("下载内容校验失败时保留当前可用库且清理无效 part", async () => {
  await withDownloadSandbox(async ({ target, validDb }) => {
    const current = Buffer.from(validDb);
    await import("node:fs/promises").then(({ writeFile }) => writeFile(target, current));
    const invalid = Buffer.from("not a sqlite database");
    globalThis.fetch = async () => new Response(invalid, {
      status: 200,
      headers: { "content-length": String(invalid.length) }
    });

    startDownload();
    await rfcDownloadTestHooks.waitForIdle();
    const status = getDownloadStatus();
    assert.equal(status.state, "failed");
    assert.match(status.error || "", /校验失败/);
    assert.deepEqual(readFileSync(target), current);
    assert.equal(rfcDownloadTestHooks.readPart(), null);
  });
});
