/*
 * 时间/时长格式化工具（从 main.tsx 抽出）。
 * 后续 ChatPanel、AgentPanel、Sidebar 等拆出的组件共用。
 * 语义必须和原 main.tsx 一致（直接复制实现，不改算法）。
 */

/** 完整时间戳：考虑秒级（<1e12）和毫秒级（>=1e12）两种输入。 */
export function formatPacketTime(timestamp?: number) {
  if (!Number.isFinite(timestamp)) return "-";
  const milliseconds = timestamp! > 1_000_000_000_000 ? timestamp! : timestamp! * 1000;
  return new Date(milliseconds).toLocaleString();
}

/** 仅时间部分（不含日期）。 */
export function formatShortPacketTime(timestamp?: number) {
  if (!Number.isFinite(timestamp)) return "-";
  const milliseconds = timestamp! > 1_000_000_000_000 ? timestamp! : timestamp! * 1000;
  return new Date(milliseconds).toLocaleTimeString();
}

/** 时间段时长。 */
export function formatDuration(start?: number, end?: number) {
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "-";
  const duration = Math.max(0, end! - start!);
  if (duration < 1) return `${Math.round(duration * 1000)}ms`;
  return `${duration.toFixed(1)}s`;
}

/** 端点（IP:Port）。 */
export function formatEndpoint(ip?: string, port?: number) {
  return `${ip || "*"}:${port ?? "*"}`;
}

/** 所有抓包节点的累计包数（从 captures 元数据求和）。 */
export function capturePacketTotal(graph?: { captures?: Array<{ packetCount?: number }> } | null): number {
  return graph?.captures?.reduce((sum, capture) => sum + (capture.packetCount || 0), 0) || 0;
}
