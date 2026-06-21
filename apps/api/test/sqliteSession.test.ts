import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { SqliteSession } from "../src/agents/sqliteSession.js";

const tempDir = mkdtempSync(path.join(tmpdir(), "pcapai-session-test-"));

test("SqliteSession: getSessionId 返回构造时传入或生成的 id", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "case-abc-123" });
  assert.equal(await s.getSessionId(), "case-abc-123");
  const s2 = new SqliteSession({ baseDir: tempDir });
  const id = await s2.getSessionId();
  assert.ok(typeof id === "string" && id.length > 0);
});

test("SqliteSession: addItems + getItems 往返", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-1" });
  await s.clearSession();
  const items = [
    { type: "message", role: "user", content: [{ type: "input_text", text: "hello" }] },
    { type: "message", role: "assistant", content: [{ type: "output_text", text: "hi" }] }
  ];
  await s.addItems(items as any);
  const got = await s.getItems();
  assert.equal(got.length, 2);
  assert.deepEqual(got, items);
});

test("SqliteSession: getItems(limit) 返回最近 N 条且按时间正序", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-2" });
  await s.clearSession();
  await s.addItems([
    { type: "message", role: "user", content: [{ type: "input_text", text: "first" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "second" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "third" }] }
  ] as any);
  const recent = await s.getItems(2);
  assert.equal(recent.length, 2);
  // 最近 2 条，正序返回
  assert.deepEqual(recent[0], { type: "message", role: "user", content: [{ type: "input_text", text: "second" }] });
  assert.deepEqual(recent[1], { type: "message", role: "user", content: [{ type: "input_text", text: "third" }] });
});

test("SqliteSession: popItem 删除并返回最后一条", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-3" });
  await s.clearSession();
  await s.addItems([
    { type: "message", role: "user", content: [{ type: "input_text", text: "a" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "b" }] }
  ] as any);
  const popped = await s.popItem();
  assert.ok(popped);
  const remaining = await s.getItems();
  assert.equal(remaining.length, 1);
});

test("SqliteSession: popItem 空时返回 undefined", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-4" });
  await s.clearSession();
  const popped = await s.popItem();
  assert.equal(popped, undefined);
});

test("SqliteSession: clearSession 清空", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-5" });
  await s.addItems([{ type: "message", role: "user", content: [{ type: "input_text", text: "x" }] }] as any);
  await s.clearSession();
  const got = await s.getItems();
  assert.equal(got.length, 0);
});

test("SqliteSession: itemCount 反映条目数", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-6" });
  await s.clearSession();
  assert.equal(s.itemCount(), 0);
  await s.addItems([
    { type: "message", role: "user", content: [{ type: "input_text", text: "1" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "2" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "3" }] }
  ] as any);
  assert.equal(s.itemCount(), 3);
});

test("SqliteSession: replaceAllWith 用摘要替换全部历史", async () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "rt-7" });
  await s.addItems([
    { type: "message", role: "user", content: [{ type: "input_text", text: "old1" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "old2" }] },
    { type: "message", role: "user", content: [{ type: "input_text", text: "old3" }] }
  ] as any);
  assert.equal(s.itemCount(), 3);
  const summary = [
    { type: "message", role: "user", content: [{ type: "input_text", text: "[压缩摘要] 3 条历史" }] }
  ];
  s.replaceAllWith(summary as any);
  assert.equal(s.itemCount(), 1);
  const got = await s.getItems();
  assert.deepEqual(got, summary);
});

test("SqliteSession: 持久化到磁盘文件", async () => {
  const s1 = new SqliteSession({ baseDir: tempDir, sessionId: "persist-1" });
  await s1.clearSession();
  await s1.addItems([{ type: "message", role: "user", content: [{ type: "input_text", text: "persisted" }] }] as any);
  s1.close();
  // 新实例读同一 sessionId，应读到持久化的数据
  const s2 = new SqliteSession({ baseDir: tempDir, sessionId: "persist-1" });
  const got = await s2.getItems();
  assert.ok(got.some((item: any) => item.content?.[0]?.text === "persisted"), "应从磁盘读到持久化数据");
  s2.close();
});

test("SqliteSession: sessionId 含特殊字符被 sanitize（防路径穿越）", () => {
  const s = new SqliteSession({ baseDir: tempDir, sessionId: "../evil/path" });
  // 验证：tempDir 下有含 evil 的 session 文件，且文件名不含路径分隔符
  const files = readdirSync(tempDir);
  const evilFiles = files.filter((f) => f.includes("evil"));
  assert.ok(evilFiles.length > 0, "应创建含 evil 的 session 文件");
  for (const f of evilFiles) {
    assert.ok(!f.includes("/") && !f.includes("\\"), `文件名不应含路径分隔符: ${f}`);
    assert.ok(f.startsWith("session-"), `文件名应以 session- 开头: ${f}`);
  }
});

test("清理临时目录", () => {
  rmSync(tempDir, { recursive: true, force: true });
  assert.equal(existsSync(tempDir), false);
});
