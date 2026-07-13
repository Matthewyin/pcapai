/*
 * RfcLibraryPanel — RFC 库管理面板（阶段 3a 双层库设置页集成）。
 *
 * 自包含组件：内部 fetch /api/rag/status + /api/rag/download/* 管理下载。
 * 显示双层库状态（完整库 / 精简库 / 无）+ 下载进度条 + 开始/取消/删除按钮。
 *
 * 双层库设计：
 *   - 精简库：桌面应用内置，开箱即用
 *   - 完整库：后台下载并支持断点续传
 *   - rfcRagService 优先完整库 → 降级精简库
 */
import React from "react";
import { CheckCircle, Download, Loader2, Trash2, XCircle } from "lucide-react";
import { rfcDownloadView, type RfcDownloadState } from "./knowledgeUiState";

type RagStatus = {
  built: boolean;
  tier?: "full" | "curated" | "none";
  docCount?: number;
  sectionCount?: number;
  sizeBytes?: number;
  builtAt?: string;
  activePath?: string;
};

type DownloadStatus = {
  taskId?: string;
  state: RfcDownloadState;
  downloadedBytes: number;
  totalBytes: number;
  bytesPerSecond: number;
  error?: string;
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatSpeed(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function RfcLibraryPanel() {
  const [ragStatus, setRagStatus] = React.useState<RagStatus | null>(null);
  const [download, setDownload] = React.useState<DownloadStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const [statusRes, dlRes] = await Promise.all([
        fetch(`/api/rag/status`),
        fetch(`/api/rag/download/status`)
      ]);
      setRagStatus(await statusRes.json());
      setDownload(await dlRes.json());
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  // 后台任务运行时轮询进度
  React.useEffect(() => {
    if (!download || !rfcDownloadView(download.state).shouldPoll) return;
    const timer = setInterval(refresh, 1500);
    return () => clearInterval(timer);
  }, [download?.state, refresh]);

  const handleStart = async () => {
    setLoading(true);
    try {
      await fetch(`/api/rag/download/start`, { method: "POST" });
      void refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    setLoading(true);
    try {
      await fetch(`/api/rag/download/cancel`, { method: "POST" });
      void refresh();
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("删除完整 RFC 库后将回退到精简库（118 篇）。确定删除？")) return;
    setLoading(true);
    try {
      await fetch(`/api/rag/download`, { method: "DELETE" });
      void refresh();
    } finally {
      setLoading(false);
    }
  };

  const tier = ragStatus?.tier;
  const isDownloading = download?.state === "downloading";
  const isValidating = download?.state === "validating";
  const progressPercent =
    download && download.totalBytes > 0
      ? Math.min(100, (download.downloadedBytes / download.totalBytes) * 100)
      : 0;

  return (
    <section className="settingsPanel rfcLibraryPanel">
      <div className="settingsPanelHeader">
        <h2>RFC 知识库</h2>
        <button onClick={() => void refresh()} disabled={loading} title="刷新状态">
          刷新
        </button>
      </div>

      {error ? <p className="status error">{error}</p> : null}

      {/* 双层库当前状态 */}
      <div className="rfcTierStatus">
        <h3>当前库状态</h3>
        {tier === "full" ? (
          <p className="tierBadge tierFull">
            <CheckCircle size={14} /> 完整库（{ragStatus?.docCount} 篇 / {formatBytes(ragStatus?.sizeBytes || 0)}）
          </p>
        ) : tier === "curated" ? (
          <p className="tierBadge tierCurated">
            <CheckCircle size={14} /> 精简库（{ragStatus?.docCount} 篇 / {formatBytes(ragStatus?.sizeBytes || 0)}）
            <small> · 完整库未下载</small>
          </p>
        ) : (
          <p className="tierBadge tierNone">
            <XCircle size={14} /> 无可用库
          </p>
        )}
        {ragStatus?.builtAt ? (
          <small className="rfcMeta">构建于 {new Date(ragStatus.builtAt).toLocaleString()}</small>
        ) : null}
      </div>

      {/* 下载进度 */}
      {download ? (
        <div className="rfcDownloadSection">
          <h3>完整库下载</h3>
          <p className="rfcDownloadHint">
            完整库覆盖完整 RFC 索引。任务在后台运行，支持取消和断点续传；校验通过后才会替换当前库。
          </p>

          {isDownloading ? (
            <>
              <div className="downloadProgress">
                <div className="progressBar" style={{ width: `${progressPercent}%` }} />
                <span className="progressText">
                  {progressPercent.toFixed(1)}% · {formatBytes(download.downloadedBytes)}
                  {download.totalBytes ? ` / ${formatBytes(download.totalBytes)}` : ""}
                  {download.bytesPerSecond ? ` · ${formatSpeed(download.bytesPerSecond)}` : ""}
                </span>
              </div>
              <div className="rfcDownloadActions">
                <button onClick={() => void handleCancel()} disabled={loading}>
                  <Loader2 size={14} className="spin" /> 取消下载
                </button>
              </div>
            </>
          ) : isValidating ? (
            <p className="status"><Loader2 size={14} className="spin" /> 下载完成，正在校验 SQLite 与索引元数据…</p>
          ) : download.state === "completed" ? (
            <p className="downloadDone">
              <CheckCircle size={14} /> 下载完成。当前使用完整库。
              <button onClick={() => void handleDelete()} disabled={loading} className="dangerLink">
                <Trash2 size={12} /> 删除回退到精简库
              </button>
            </p>
          ) : download.state === "failed" ? (
            <>
              <p className="status error">下载失败：{download.error}</p>
              <button onClick={() => void handleStart()} disabled={loading}>
                <Download size={14} /> 重新下载
              </button>
            </>
          ) : download.state === "paused" ? (
            <>
              <p className="status">已暂停（已下载 {formatBytes(download.downloadedBytes)}，支持续传）</p>
              <button onClick={() => void handleStart()} disabled={loading}>
                <Download size={14} /> 继续下载
              </button>
            </>
          ) : tier === "full" ? (
            <p className="rfcAlreadyFull">完整库已就绪，无需下载。</p>
          ) : (
            <button onClick={() => void handleStart()} disabled={loading} className="primary">
              <Download size={14} /> 下载完整库
            </button>
          )}
        </div>
      ) : null}
    </section>
  );
}
