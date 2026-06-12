// Electron 主进程：以 sidecar 子进程方式启动 Express API、隔离 userData 数据目录、托管主窗口。
// 开发模式：API 子进程走 tsx，窗口加载 Vite dev server（30023）。
// 生产模式：API 子进程走 node + 编译产物，窗口加载 apps/web/dist。
import { app, BrowserWindow, Menu, shell } from "electron";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = process.env.PCAPAI_DESKTOP_MODE === "dev" || !app.isPackaged;
const workspaceRoot = isDev
  ? path.resolve(__dirname, "../../..")
  : path.resolve(process.resourcesPath, "app");

let apiChild: ChildProcess | null = null;
let isQuitting = false;

function readApiConfig() {
  const configPath = path.join(workspaceRoot, "config/defaults.json");
  const raw = JSON.parse(readFileSync(configPath, "utf8")) as { api: { host: string; port: number } };
  return { host: raw.api.host, port: raw.api.port, configPath };
}

function buildSidecarEnv() {
  const userData = app.getPath("userData");
  const dirs = {
    cases: path.join(userData, "cases"),
    rfcIndex: path.join(userData, "rfc-index")
  };
  for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true });

  const env: NodeJS.ProcessEnv = { ...process.env, PCAPAI_ROOT: workspaceRoot };
  if (!isDev) {
    env.PCAPAI_CASE_DATA_DIR ??= dirs.cases;
    env.PCAPAI_RAG_INDEX_PATH ??= path.join(dirs.rfcIndex, "rfc.db");
    env.PCAPAI_LEARNED_PATTERNS_PATH ??= path.join(userData, "learned_patterns.json");
    const bundledRfc = path.join(workspaceRoot, "RFC");
    if (existsSync(bundledRfc)) env.PCAPAI_RAG_RFC_DIR ??= bundledRfc;
    // 生产期 MCP 走编译产物（Resources 内置 node + dist），免 npm 依赖
    const mcpTshark = path.join(workspaceRoot, "mcp/tshark-query/dist/index.js");
    const mcpEvidence = path.join(workspaceRoot, "mcp/evidence-opener/dist/index.js");
    if (existsSync(mcpTshark)) {
      env.PCAPAI_TSHARK_QUERY_MCP_COMMAND ??= process.execPath;
      env.PCAPAI_TSHARK_QUERY_MCP_ARGS ??= mcpTshark;
    }
    if (existsSync(mcpEvidence)) {
      env.PCAPAI_EVIDENCE_OPENER_MCP_COMMAND ??= process.execPath;
      env.PCAPAI_EVIDENCE_OPENER_MCP_ARGS ??= mcpEvidence;
    }
  }
  return env;
}

async function waitForHealth(host: string, port: number, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://${host}:${port}/api/health`, { signal: AbortSignal.timeout(1500) });
      if (response.ok) return;
    } catch {
      // 忽略，继续重试
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error(`API 未在 ${timeoutMs}ms 内就绪（${host}:${port}）`);
}

async function startApiSidecar() {
  const { host, port } = readApiConfig();
  const apiSrc = path.join(workspaceRoot, "apps/api/src/index.ts");
  const apiDist = path.join(workspaceRoot, "apps/api/dist/apps/api/src/index.js");
  const useDevTsx = isDev && existsSync(apiSrc);
  const command = useDevTsx ? "npx" : process.execPath;
  const args = useDevTsx ? ["tsx", apiSrc] : [apiDist];

  apiChild = spawn(command, args, {
    cwd: workspaceRoot,
    env: buildSidecarEnv(),
    stdio: ["ignore", "inherit", "inherit"]
  });
  apiChild.on("exit", (code) => {
    console.error(`API sidecar exited code=${code}`);
    apiChild = null;
    if (!isQuitting && code !== 0) app.quit();
  });
  await waitForHealth(host, port);
  return { host, port };
}

function stopApiSidecar() {
  if (apiChild?.pid) {
    try { process.kill(apiChild.pid, "SIGTERM"); } catch { /* 进程可能已退出 */ }
    apiChild = null;
  }
}

async function createMainWindow(apiUrl: string) {
  const win = new BrowserWindow({
    width: 1480,
    height: 920,
    minWidth: 1100,
    minHeight: 700,
    title: "pcapAI",
    titleBarStyle: "hiddenInset",
    backgroundColor: "#0d1117",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("http")) shell.openExternal(url);
    return { action: "deny" };
  });
  if (isDev) {
    const devUrl = process.env.PCAPAI_WEB_DEV_URL || "http://127.0.0.1:30023";
    await win.loadURL(devUrl);
  } else {
    await win.loadFile(path.join(workspaceRoot, "apps/web/dist/index.html"));
  }
  win.webContents.executeJavaScript(`window.__PCAPAI_API__ = ${JSON.stringify(apiUrl)};`).catch(() => {});
}

function buildApplicationMenu() {
  const template: Electron.MenuItemConstructorOptions[] = [
    { role: "appMenu" },
    {
      label: "File",
      submenu: [
        { label: "New Case", accelerator: "CmdOrCtrl+N", click: () => BrowserWindow.getFocusedWindow()?.webContents.executeJavaScript("window.dispatchEvent(new CustomEvent('pcapai:new-case'))") },
        { label: "Open pcap…", accelerator: "CmdOrCtrl+O", click: () => BrowserWindow.getFocusedWindow()?.webContents.executeJavaScript("window.dispatchEvent(new CustomEvent('pcapai:open-pcap'))") },
        { type: "separator" },
        { role: "close" }
      ]
    },
    { role: "editMenu" },
    { role: "viewMenu" },
    { role: "windowMenu" },
    { role: "help", submenu: [{ label: "GitHub", click: () => shell.openExternal("https://github.com/Matthewyin/pcapai") }] }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(async () => {
  buildApplicationMenu();
  try {
    const { host, port } = await startApiSidecar();
    await createMainWindow(`http://${host}:${port}`);
  } catch (error) {
    console.error("Boot failed:", error);
    app.quit();
    return;
  }
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow(`http://${readApiConfig().host}:${readApiConfig().port}`);
  });
});

app.on("before-quit", () => {
  isQuitting = true;
  stopApiSidecar();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
