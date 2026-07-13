import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync } from "node:fs";
import { open } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
import Database from "better-sqlite3";
import { apiConfig } from "../config.js";
import { resetRfcIndexCache } from "./rfcRagService.js";

export type DownloadStatus = {
  taskId?: string;
  state: "idle" | "downloading" | "validating" | "paused" | "completed" | "failed";
  downloadedBytes: number;
  totalBytes: number;
  bytesPerSecond: number;
  error?: string;
  targetPath: string;
  startedAt?: number;
  completedAt?: number;
};

type ValidationResult = { valid: true } | { valid: false; error: string };

function resolveDownloadPath(): string {
  return process.env.PCAPAI_RAG_INDEX_PATH
    ? path.resolve(process.env.PCAPAI_RAG_INDEX_PATH)
    : apiConfig.rag.indexPath;
}

let currentStatus: DownloadStatus = idleStatus();
let abortController: AbortController | null = null;
let currentTask: Promise<void> | null = null;
let activeGeneration = 0;
let speedSampler: ReturnType<typeof setInterval> | null = null;

function idleStatus(): DownloadStatus {
  return {
    state: "idle",
    downloadedBytes: 0,
    totalBytes: 0,
    bytesPerSecond: 0,
    targetPath: resolveDownloadPath()
  };
}

function stopSpeedSampler(): void {
  if (speedSampler) clearInterval(speedSampler);
  speedSampler = null;
}

function startSpeedSampler(resumeFrom: number): void {
  let lastSampleTime = Date.now();
  let lastSampleBytes = resumeFrom;
  stopSpeedSampler();
  speedSampler = setInterval(() => {
    const now = Date.now();
    const elapsed = (now - lastSampleTime) / 1000;
    if (elapsed > 0) {
      currentStatus.bytesPerSecond = Math.round((currentStatus.downloadedBytes - lastSampleBytes) / elapsed);
      lastSampleTime = now;
      lastSampleBytes = currentStatus.downloadedBytes;
    }
  }, 1000);
}

export function validateDownloadedRfcDb(filePath: string): ValidationResult {
  let database: Database.Database | null = null;
  try {
    database = new Database(filePath, { readonly: true, fileMustExist: true });
    const quickCheck = database.pragma("quick_check") as Array<{ quick_check?: string }>;
    if (!quickCheck.length || quickCheck.some((row) => row.quick_check !== "ok")) {
      return { valid: false, error: "SQLite quick_check 未通过" };
    }
    const tables = new Set(
      (database.prepare("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')").all() as Array<{ name: string }>).map((row) => row.name)
    );
    for (const required of ["meta", "docs", "sections", "sections_fts"]) {
      if (!tables.has(required)) return { valid: false, error: `RFC 索引缺少 ${required} 表` };
    }
    const meta = Object.fromEntries(
      (database.prepare("SELECT key, value FROM meta").all() as Array<{ key: string; value: string }>).map((row) => [row.key, row.value])
    );
    const docCount = Number(meta.docCount);
    const sectionCount = Number(meta.sectionCount);
    if (!meta.builtAt || !Number.isFinite(Date.parse(meta.builtAt)) || docCount <= 0 || sectionCount <= 0) {
      return { valid: false, error: "RFC 索引 meta 信息不完整" };
    }
    const actualDocCount = Number((database.prepare("SELECT COUNT(*) AS count FROM docs").get() as { count: number }).count);
    const actualSectionCount = Number((database.prepare("SELECT COUNT(*) AS count FROM sections").get() as { count: number }).count);
    if (actualDocCount !== docCount || actualSectionCount !== sectionCount) {
      return { valid: false, error: "RFC 索引 meta 计数与实际数据不一致" };
    }
    return { valid: true };
  } catch (error) {
    return { valid: false, error: error instanceof Error ? error.message : String(error) };
  } finally {
    database?.close();
  }
}

export function getDownloadStatus(): DownloadStatus {
  const targetPath = resolveDownloadPath();
  if (currentStatus.targetPath !== targetPath && !currentTask) currentStatus = idleStatus();
  return { ...currentStatus };
}

function totalBytesFrom(response: Response, resumeFrom: number): number {
  const contentRange = response.headers.get("content-range");
  const rangeTotal = contentRange?.match(/\/([0-9]+)$/)?.[1];
  if (rangeTotal) return Number(rangeTotal);
  const contentLength = Number(response.headers.get("content-length") || 0);
  return response.status === 206 ? resumeFrom + contentLength : contentLength;
}

async function runDownload(generation: number, controller: AbortController): Promise<void> {
  const targetPath = currentStatus.targetPath;
  const partPath = `${targetPath}.part`;
  let resumeFrom = existsSync(partPath) ? statSync(partPath).size : 0;
  try {
    const headers: Record<string, string> = {};
    if (resumeFrom > 0) headers.Range = `bytes=${resumeFrom}-`;
    const response = await fetch(apiConfig.rag.download.url, { signal: controller.signal, headers });
    if (!response.ok) throw new Error(`下载源返回 ${response.status} ${response.statusText}`);
    if (!response.body) throw new Error("下载响应没有 body 流");

    if (resumeFrom > 0 && response.status === 206) {
      const rangeStart = Number(response.headers.get("content-range")?.match(/^bytes\s+(\d+)-/i)?.[1]);
      if (!Number.isFinite(rangeStart) || rangeStart !== resumeFrom) {
        throw new Error("下载源返回的断点位置与本地文件不一致");
      }
    } else if (response.status !== 206) {
      resumeFrom = 0;
      currentStatus.downloadedBytes = 0;
    }
    currentStatus.totalBytes = totalBytesFrom(response, resumeFrom);
    startSpeedSampler(resumeFrom);

    const file = await open(partPath, resumeFrom > 0 && response.status === 206 ? "a" : "w");
    try {
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value?.length) {
          await file.write(value);
          currentStatus.downloadedBytes += value.length;
        }
      }
    } finally {
      await file.close();
    }

    if (generation !== activeGeneration || controller.signal.aborted) return;
    currentStatus.state = "validating";
    currentStatus.bytesPerSecond = 0;
    stopSpeedSampler();
    const validation = validateDownloadedRfcDb(partPath);
    if (!validation.valid) {
      rmSync(partPath, { force: true });
      throw new Error(`RFC 索引校验失败：${validation.error}`);
    }

    resetRfcIndexCache();
    renameSync(partPath, targetPath);
    currentStatus.state = "completed";
    currentStatus.completedAt = Date.now();
  } catch (error) {
    if (generation !== activeGeneration) return;
    if (controller.signal.aborted) {
      currentStatus.state = "paused";
      delete currentStatus.error;
    } else {
      currentStatus.state = "failed";
      currentStatus.error = error instanceof Error ? error.message : String(error);
    }
  } finally {
    if (generation === activeGeneration) {
      stopSpeedSampler();
      abortController = null;
    }
  }
}

export function startDownload(): DownloadStatus {
  if (currentTask) return getDownloadStatus();
  const targetPath = resolveDownloadPath();
  const partPath = `${targetPath}.part`;
  mkdirSync(path.dirname(targetPath), { recursive: true });
  const resumeFrom = existsSync(partPath) ? statSync(partPath).size : 0;
  const controller = new AbortController();
  const generation = ++activeGeneration;
  abortController = controller;
  currentStatus = {
    taskId: randomUUID(),
    state: "downloading",
    downloadedBytes: resumeFrom,
    totalBytes: 0,
    bytesPerSecond: 0,
    targetPath,
    startedAt: Date.now()
  };
  currentTask = Promise.resolve()
    .then(() => runDownload(generation, controller))
    .finally(() => { currentTask = null; });
  return getDownloadStatus();
}

export function cancelDownload(): DownloadStatus {
  abortController?.abort();
  if (currentStatus.state === "downloading" || currentStatus.state === "validating") {
    currentStatus.state = "paused";
    currentStatus.bytesPerSecond = 0;
  }
  return getDownloadStatus();
}

export function deleteDownloadedDb(): { deleted: boolean; path: string } {
  const targetPath = resolveDownloadPath();
  activeGeneration += 1;
  abortController?.abort();
  abortController = null;
  stopSpeedSampler();
  let deleted = false;
  for (const candidate of [targetPath, `${targetPath}.part`]) {
    if (!existsSync(candidate)) continue;
    rmSync(candidate, { force: true });
    deleted = true;
  }
  resetRfcIndexCache();
  currentStatus = idleStatus();
  return { deleted, path: targetPath };
}

export const rfcDownloadTestHooks = {
  waitForIdle: async () => { await currentTask; },
  reset: async () => {
    abortController?.abort();
    activeGeneration += 1;
    await currentTask;
    currentTask = null;
    abortController = null;
    stopSpeedSampler();
    currentStatus = idleStatus();
  },
  readPart: () => {
    const partPath = `${resolveDownloadPath()}.part`;
    return existsSync(partPath) ? readFileSync(partPath) : null;
  }
};
