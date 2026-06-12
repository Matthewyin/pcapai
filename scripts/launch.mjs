// pcapAI 本地启动器：确保前端已构建 → 起 API（同源托管前端）→ 等就绪 → 开浏览器独立窗口。
// 用法：npm run launch  或双击 pcapAI.command。Ctrl+C 退出并停服务。
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaults = JSON.parse(readFileSync(path.join(root, "config/defaults.json"), "utf8"));
const host = process.env.PCAPAI_API_HOST || defaults.api.host;
const port = Number(process.env.PCAPAI_API_PORT || defaults.api.port);
const url = `http://${host}:${port}`;

function log(message) { console.log(`\x1b[38;5;208m▸ pcapAI\x1b[0m ${message}`); }

// 1. 确保前端构建产物存在（缺失则构建一次）
const webDist = path.join(root, "apps/web/dist/index.html");
if (!existsSync(webDist)) {
  log("首次启动，正在构建前端…");
  spawnSync("npm", ["run", "build", "-w", "apps/web"], { cwd: root, stdio: "inherit" });
}

// 2. 起 API（同源托管前端）
log(`启动服务 ${url} …`);
const apiEntry = existsSync(path.join(root, "apps/api/dist/apps/api/src/index.js"))
  ? path.join(root, "apps/api/dist/apps/api/src/index.js")
  : null;
const api = apiEntry
  ? spawn(process.execPath, [apiEntry], { cwd: root, env: { ...process.env, PCAPAI_SERVE_WEB: "1" }, stdio: "inherit" })
  : spawn("npx", ["tsx", "apps/api/src/index.ts"], { cwd: root, env: { ...process.env, PCAPAI_SERVE_WEB: "1" }, stdio: "inherit" });

// 3. 等健康检查通过
async function waitForHealth(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(1500) });
      if (response.ok) return true;
    } catch { /* 重试 */ }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  return false;
}

// 4. 开浏览器独立窗口：优先 Chrome --app（无地址栏，像 app），否则系统默认浏览器
function openAppWindow() {
  const chromePaths = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium"
  ];
  const chrome = chromePaths.find((candidate) => existsSync(candidate));
  if (chrome) {
    spawn(chrome, [`--app=${url}`, "--class=pcapAI"], { detached: true, stdio: "ignore" }).unref();
    log("已在独立窗口中打开（Chrome app 模式）。");
  } else {
    try { execFileSync("open", [url]); log("已在默认浏览器中打开。"); }
    catch { log(`请手动在浏览器打开：${url}`); }
  }
}

function shutdown() {
  log("正在停止服务…");
  if (api.pid) { try { process.kill(api.pid, "SIGTERM"); } catch { /* 已退出 */ } }
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
api.on("exit", (code) => { if (code) { log(`服务退出（code=${code}）`); process.exit(code); } });

if (await waitForHealth()) {
  openAppWindow();
  log("运行中。关闭此终端或按 Ctrl+C 退出。");
} else {
  log("服务启动超时，请检查日志。");
  shutdown();
}
