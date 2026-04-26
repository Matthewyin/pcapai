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
  unlinkSync(inputPath);
  return outputPath;
}
