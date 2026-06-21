import { execFile } from "node:child_process";
import { unlinkSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { apiConfig } from "../config.js";

const execFileAsync = promisify(execFile);

export async function stripPayload(inputPath: string) {
  if (!apiConfig.payloadTrim.enabled) return inputPath;

  const parsed = path.parse(inputPath);
  const outputPath = path.join(parsed.dir, `${parsed.name}.headers${parsed.ext || ".pcap"}`);
  await execFileAsync(apiConfig.payloadTrim.editcapCommand, [
    "-s",
    String(apiConfig.payloadTrim.snaplen),
    inputPath,
    outputPath
  ]);
  // 原始 pcap 删除失败（权限/占用）不应让已成功 trim 的上传整体失败
  try {
    unlinkSync(inputPath);
  } catch {
    /* trim 已完成，原始文件残留不影响后续使用 headers 文件 */
  }
  return outputPath;
}
