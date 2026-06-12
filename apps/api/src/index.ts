import "dotenv/config";
import cors from "cors";
import express from "express";
import { apiConfig } from "./config.js";
import { createAgentRouter } from "./http/routes.js";

// 可被外部（如 Electron 主进程）import 调用：返回监听就绪的 Promise
export async function startApi(): Promise<{ host: string; port: number }> {
  const app = express();
  app.use(cors({ origin: apiConfig.corsOrigins }));
  app.use(express.json({ limit: apiConfig.jsonLimit }));
  app.use("/api", createAgentRouter());
  app.get("/", (_req, res) => res.json({ service: "pcapAI JS agent API", docs: "/api/health" }));
  return new Promise((resolve) => {
    app.listen(apiConfig.port, apiConfig.host, () => {
      console.log(`pcapAI API listening on http://${apiConfig.host}:${apiConfig.port}`);
      resolve({ host: apiConfig.host, port: apiConfig.port });
    });
  });
}

// 直接 node/tsx 启动时立即跑；被 import 时由调用方决定时机
const isDirectRun = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isDirectRun) {
  startApi().catch((error) => { console.error(error); process.exit(1); });
}
