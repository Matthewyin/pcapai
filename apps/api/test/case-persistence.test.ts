import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { CaseGraph } from "../../../packages/shared/src/index.js";
import { readCaseGraph, writeCaseGraph } from "../src/http/caseStore.js";
import { caseRunLockTestHooks, withCaseRunLock } from "../src/http/caseRunLock.js";

function graph(title: string): CaseGraph {
  return {
    spec: { caseId: "atomic-case", title, createdAt: new Date().toISOString() },
    captures: [],
    mappingHints: [],
    timeOffsetHints: [],
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [],
    analysisRuns: [],
    toolRuns: [],
    insights: [],
    connectionLinks: [],
    memory: { topology: "", findings: [], userNotes: [] }
  };
}

test("CaseGraph 使用同目录临时文件原子替换且不残留临时文件", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pcapai-case-atomic-"));
  process.env.PCAPAI_CASE_DATA_DIR = root;
  try {
    writeCaseGraph(graph("第一版"));
    writeCaseGraph(graph("第二版"));
    assert.equal(readCaseGraph("atomic-case").spec.title, "第二版");
    assert.deepEqual(readdirSync(path.join(root, "atomic-case")), ["case.json"]);
  } finally {
    delete process.env.PCAPAI_CASE_DATA_DIR;
    rmSync(root, { recursive: true, force: true });
  }
});

test("序列化失败时保留原 CaseGraph", () => {
  const root = mkdtempSync(path.join(tmpdir(), "pcapai-case-atomic-failure-"));
  process.env.PCAPAI_CASE_DATA_DIR = root;
  try {
    writeCaseGraph(graph("可用版本"));
    const before = readFileSync(path.join(root, "atomic-case", "case.json"), "utf8");
    const invalid = graph("损坏版本") as CaseGraph & { circular?: unknown };
    invalid.circular = invalid;
    assert.throws(() => writeCaseGraph(invalid));
    assert.equal(readFileSync(path.join(root, "atomic-case", "case.json"), "utf8"), before);
  } finally {
    delete process.env.PCAPAI_CASE_DATA_DIR;
    rmSync(root, { recursive: true, force: true });
  }
});

test("同 case 的读改写串行，不同 case 可并行", async () => {
  caseRunLockTestHooks.reset();
  const events: string[] = [];
  let releaseFirst!: () => void;
  const gate = new Promise<void>((resolve) => { releaseFirst = resolve; });

  const first = withCaseRunLock("case-a", async () => {
    events.push("a1-start");
    await gate;
    events.push("a1-end");
  });
  const second = withCaseRunLock("case-a", async () => {
    events.push("a2-start");
  });
  const other = withCaseRunLock("case-b", async () => {
    events.push("b-start");
  });

  await other;
  assert.deepEqual(events, ["a1-start", "b-start"]);
  releaseFirst();
  await Promise.all([first, second]);
  assert.deepEqual(events, ["a1-start", "b-start", "a1-end", "a2-start"]);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(caseRunLockTestHooks.activeCaseCount(), 0);
});
