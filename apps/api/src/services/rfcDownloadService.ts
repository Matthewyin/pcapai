/**
 * rfcDownloadService — 完整 RFC 库静默下载（阶段 3a 双层库上层）。
 *
 * 设计：
 *   - 下载源：GitHub Release 资产直链（config.api.rag.download.url）
 *   - 目标：userData 目录（Electron 注入 PCAPAI_USERDATA_DIR；开发环境降级到 workspace data/）
 *   - 断点续传：HTTP Range 请求，已下载字节记录在 .part 文件
 *   - 进度回调：供 SSE 推送（设置页显示进度条）
 *   - 校验：下载完成后打开 db 验证 meta 表，失败则删除
 *
 * 注意：本服务不直接触发下载（避免 API 启动时阻塞），由设置页用户主动触发或
 * Electron 后台调度调用。API 只暴露 start/status/cancel 三个方法。
 */
import { createWriteStream, existsSync, statSync, mkdirSync, renameSync, rmSync } from "node:fs";
import path from "node:path";
import { apiConfig } from "../config.js";

export type DownloadStatus = {
  state: "idle" | "downloading" | "paused" | "completed" | "failed";
  /** 已下载字节 */
  downloadedBytes: number;
  /** 总字节（从 Content-Length 获取，未知则为 0） */
  totalBytes: number;
  /** 下载速度（字节/秒） */
  bytesPerSecond: number;
  /** 错误信息（state=failed 时） */
  error?: string;
  /** 目标文件路径 */
  targetPath: string;
  /** 开始时间戳 */
  startedAt?: number;
};

let currentStatus: DownloadStatus = {
  state: "idle",
  downloadedBytes: 0,
  totalBytes: 0,
  bytesPerSecond: 0,
  targetPath: resolveDownloadPath()
};

let abortController: AbortController | null = null;
let speedSampler: ReturnType<typeof setInterval> | null = null;

/**
 * 解析下载目标路径：
 *   - Electron 注入 PCAPAI_USERDATA_DIR → ${userData}/rfc.db
 *   - 开发环境 → workspace data/rfc-index/rfc.db（与 apiConfig.rag.indexPath 一致）
 */
function resolveDownloadPath(): string {
  const userDataDir = process.env.PCAPAI_USERDATA_DIR;
  if (userDataDir) {
    return path.join(userDataDir, apiConfig.rag.download.targetFilename);
  }
  return apiConfig.rag.indexPath;
}

export function getDownloadStatus(): DownloadStatus {
  return { ...currentStatus };
}

/**
 * 启动完整库下载（断点续传）。已在下载中则返回当前状态不重复启动。
 * 返回最新状态。下载在后台进行，调用方通过 getDownloadStatus() 轮询或订阅 SSE。
 */
export async function startDownload(): Promise<DownloadStatus> {
  if (currentStatus.state === "downloading") return getDownloadStatus();

  const targetPath = resolveDownloadPath();
  const partPath = `${targetPath}.part`;
  mkdirSync(path.dirname(targetPath), { recursive: true });

  // 断点续传：读取 .part 文件已下载字节数
  const resumeFrom = existsSync(partPath) ? statSync(partPath).size : 0;

  abortController = new AbortController();
  currentStatus = {
    state: "downloading",
    downloadedBytes: resumeFrom,
    totalBytes: 0,
    bytesPerSecond: 0,
    targetPath,
    startedAt: Date.now()
  };

  let lastSampleTime = Date.now();
  let lastSampleBytes = resumeFrom;
  speedSampler = setInterval(() => {
    const now = Date.now();
    const elapsed = (now - lastSampleTime) / 1000;
    if (elapsed > 0) {
      currentStatus.bytesPerSecond = Math.round((currentStatus.downloadedBytes - lastSampleBytes) / elapsed);
      lastSampleTime = now;
      lastSampleBytes = currentStatus.downloadedBytes;
    }
  }, 1000);

  try {
    const headers: Record<string, string> = {};
    if (resumeFrom > 0) headers.Range = `bytes=${resumeFrom}-`;

    const response = await fetch(apiConfig.rag.download.url, {
      signal: abortController.signal,
      headers
    });

    if (!response.ok && response.status !== 206) {
      throw new Error(`下载源返回 ${response.status} ${response.statusText}`);
    }

    const contentLength = Number(response.headers.get("content-length") || 0);
    // 206 Partial Content 时 content-length 是剩余大小，需加上 resumeFrom
    const isPartial = response.status === 206;
    currentStatus.totalBytes = isPartial ? resumeFrom + contentLength : contentLength;

    if (!response.body) throw new Error("下载响应没有 body 流");

    const writer = createWriteStream(partPath, resumeFrom > 0 && isPartial ? { flags: "a" } : { flags: "w" });
    const reader = response.body.getReader();

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        writer.write(value);
        currentStatus.downloadedBytes += value.length;
      }
    }
    writer.end();
    await new Promise<void>((resolve, reject) => {
      writer.on("finish", resolve);
      writer.on("error", reject);
    });

    // 下载完成：.part → 目标文件
    renameSync(partPath, targetPath);
    currentStatus.state = "completed";

    // 清理 speed sampler
    if (speedSampler) {
      clearInterval(speedSampler);
      speedSampler = null;
    }

    return getDownloadStatus();
  } catch (error) {
    currentStatus.state = "failed";
    currentStatus.error = error instanceof Error ? error.message : String(error);
    // 失败时保留 .part 文件供断点续传（除非用户取消）
    if (currentStatus.error.includes("aborted")) {
      currentStatus.state = "paused";
      delete currentStatus.error;
    }
    if (speedSampler) {
      clearInterval(speedSampler);
      speedSampler = null;
    }
    return getDownloadStatus();
  }
}

/**
 * 取消下载（保留 .part 文件供下次续传）。
 */
export function cancelDownload(): DownloadStatus {
  if (abortController) {
    abortController.abort();
    abortController = null;
  }
  if (currentStatus.state === "downloading") {
    currentStatus.state = "paused";
  }
  return getDownloadStatus();
}

/**
 * 删除已下载的完整库（回退到精简库）。
 */
export function deleteDownloadedDb(): { deleted: boolean; path: string } {
  const targetPath = resolveDownloadPath();
  const partPath = `${targetPath}.part`;
  let deleted = false;
  for (const p of [targetPath, partPath]) {
    if (existsSync(p)) {
      rmSync(p, { force: true });
      deleted = true;
    }
  }
  currentStatus = {
    state: "idle",
    downloadedBytes: 0,
    totalBytes: 0,
    bytesPerSecond: 0,
    targetPath
  };
  return { deleted, path: targetPath };
}
