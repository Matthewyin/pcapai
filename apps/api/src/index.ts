import "dotenv/config";
import { existsSync } from "node:fs";
import path from "node:path";
import cors from "cors";
import express from "express";
import { apiConfig } from "./config.js";
import { createAgentRouter } from "./http/routes.js";
import { closeMcpResources } from "./mcp/mcpRegistry.js";

// 可被外部（如启动器脚本）import 调用：返回监听就绪的 Promise
export async function startApi(): Promise<{ host: string; port: number }> {
  const app = express();
  app.use(cors({ origin: apiConfig.corsOrigins }));
  app.use(express.json({ limit: apiConfig.jsonLimit }));
  app.use("/api", createAgentRouter());

  // 本地自用模式：同源托管前端构建产物，/api 之后挂载，SPA fallback 到 index.html
  if (apiConfig.serveWeb && existsSync(apiConfig.webDistPath)) {
    const indexHtml = path.join(apiConfig.webDistPath, "index.html");
    app.use(express.static(apiConfig.webDistPath));
    // 静态未命中且非 API 的 GET 请求回退到 SPA 入口（Express 5 用中间件，避免通配符路由语法坑）
    app.use((req, res, next) => {
      if (req.method !== "GET" || req.path.startsWith("/api/")) return next();
      res.sendFile(indexHtml);
    });
  } else {
    app.get("/", (_req, res) => res.json({ service: "pcapAI JS agent API", docs: "/api/health" }));
  }

  return new Promise((resolve) => {
    app.listen(apiConfig.port, apiConfig.host, () => {
      const where = apiConfig.serveWeb ? "（含前端）" : "";
      console.log(`pcapAI API listening on http://${apiConfig.host}:${apiConfig.port}${where}`);
      resolve({ host: apiConfig.host, port: apiConfig.port });
    });
  });
}

// 直接 node/tsx 启动时立即跑；被 import 时由调用方决定时机
const isDirectRun = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isDirectRun) {
  const shutdown = () => {
    closeMcpResources().finally(() => process.exit(0));
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
  startApi().catch((error) => { console.error(error); process.exit(1); });
}
