// Electron 主进程：以 sidecar 子进程方式启动 Express API、隔离 userData 数据目录、托管主窗口。
// 开发模式：API 子进程走 tsx，窗口加载 Vite dev server（30023）。
// 生产模式：API 子进程走 node + 编译产物，窗口加载 apps/web/dist。
import { app, BrowserWindow, dialog, ipcMain, Menu, shell } from "electron";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import path from "node:path";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import keytar from "keytar";

const KEYCHAIN_SERVICE = "pcapAI";
const KEYCHAIN_LLM_ACCOUNT = "llm-api-key";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = process.env.PCAPAI_DESKTOP_MODE === "dev" || !app.isPackaged;
const workspaceRoot = isDev
  ? path.resolve(__dirname, "../../..")
  : path.resolve(process.resourcesPath, "app");

let apiChild: ChildProcess | null = null;
let isQuitting = false;
let mainWindow: BrowserWindow | null = null;
let cachedLlmKey: string | null = null;
// 启动时 / 二次双击 .pcap 时的文件待办；窗口就绪后回放
const pendingPcapFiles: string[] = [];

function dispatchOpenPcap(filePath: string) {
  pendingPcapFiles.push(filePath);
  flushPendingPcap();
}
function flushPendingPcap() {
  if (!mainWindow || !mainWindow.webContents || mainWindow.webContents.isLoading()) return;
  while (pendingPcapFiles.length) {
    const next = pendingPcapFiles.shift();
    if (!next) break;
    mainWindow.webContents.executeJavaScript(
      `window.dispatchEvent(new CustomEvent('pcapai:open-pcap-file', { detail: ${JSON.stringify(next)} }))`
    ).catch(() => {});
  }
}

// 系统依赖检测：tshark 套件与 Wireshark.app 是本 app 的硬依赖，缺失要在启动时阻断并引导
function checkSystemDependencies(): { ok: boolean; missing: string[] } {
  const cliTools = ["tshark", "editcap", "capinfos"];
  const missing: string[] = [];
  for (const tool of cliTools) {
    const result = spawnSync("which", [tool], { stdio: ["ignore", "ignore", "ignore"] });
    if (result.status !== 0) missing.push(tool);
  }
  // Wireshark.app 仅用于打开 evidence；缺失只警告不阻断
  const wiresharkPath = "/Applications/Wireshark.app";
  const result = spawnSync("test", ["-d", wiresharkPath], { stdio: ["ignore", "ignore", "ignore"] });
  if (result.status !== 0) missing.push("Wireshark.app（用于复核证据）");
  return { ok: missing.filter((item) => !item.includes("Wireshark")).length === 0, missing };
}

async function ensureDependencies() {
  const { ok, missing } = checkSystemDependencies();
  if (!missing.length) return;
  const blocking = !ok;
  const result = await dialog.showMessageBox({
    type: blocking ? "error" : "warning",
    title: blocking ? "缺少系统依赖" : "建议安装",
    message: blocking ? "pcapAI 需要 Wireshark 套件提供的命令才能解析数据包。" : "未检测到 Wireshark.app，证据复核功能将不可用。",
    detail: `检测缺失：${missing.join("、")}\n\n推荐方案：访问 https://www.wireshark.org/download.html 下载安装；或在终端执行：\n  brew install --cask wireshark\n安装完成后重新启动 pcapAI。`,
    buttons: blocking ? ["前往下载", "退出"] : ["前往下载", "继续"],
    defaultId: 0,
    cancelId: 1
  });
  if (result.response === 0) await shell.openExternal("https://www.wireshark.org/download.html");
  if (blocking) {
    app.quit();
    throw new Error("missing system dependencies");
  }
}

function readApiConfig() {
  const configPath = path.join(workspaceRoot, "config/defaults.json");
  const raw = JSON.parse(readFileSync(configPath, "utf8")) as { api: { host: string; port: number } };
  return { host: raw.api.host, port: raw.api.port, configPath };
}

async function readLlmKeyFromKeychain(): Promise<string | null> {
  try { return await keytar.getPassword(KEYCHAIN_SERVICE, KEYCHAIN_LLM_ACCOUNT); }
  catch (error) { console.warn("Keychain 读取失败：", error); return null; }
}

function registerIpcHandlers() {
  ipcMain.handle("pcapai:secrets:get-llm-key", async () => {
    const value = await readLlmKeyFromKeychain();
    // 只返回是否设置，不回传明文，避免渲染层泄漏
    return { configured: Boolean(value) };
  });
  ipcMain.handle("pcapai:secrets:set-llm-key", async (_event, value: string) => {
    if (typeof value !== "string" || !value.trim()) throw new Error("LLM Key 不能为空");
    await keytar.setPassword(KEYCHAIN_SERVICE, KEYCHAIN_LLM_ACCOUNT, value.trim());
    // 同时同步到 API 进程：写 env 在已运行的子进程上不生效，提示用户重启
    return { ok: true, restartRequired: Boolean(apiChild) };
  });
  ipcMain.handle("pcapai:secrets:clear-llm-key", async () => {
    await keytar.deletePassword(KEYCHAIN_SERVICE, KEYCHAIN_LLM_ACCOUNT);
    return { ok: true, restartRequired: Boolean(apiChild) };
  });
}

function buildSidecarEnv() {
  const userData = app.getPath("userData");
  const dirs = {
    cases: path.join(userData, "cases"),
    rfcIndex: path.join(userData, "rfc-index")
  };
  for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true });

  const env: NodeJS.ProcessEnv = { ...process.env, PCAPAI_ROOT: workspaceRoot };
  // Keychain 中的 LLM Key 在 spawn 前注入；优先于 .env 文件（API 读 process.env）
  if (cachedLlmKey) env.PCAPAI_LLM_API_KEY = cachedLlmKey;
  if (!isDev) {
    // 生产期 sidecar 与其 spawn 的 MCP 子进程都用 Electron 二进制当 node 运行时，
    // 必须设此变量让 execPath 以纯 node 模式启动（否则会拉起 GUI 实例）。
    // native module（better-sqlite3 / keytar）均为 N-API，Electron ABI 130 下实测可加载。
    env.ELECTRON_RUN_AS_NODE = "1";
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
  if (mainWindow) { mainWindow.focus(); return; }
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
      sandbox: false,
      preload: path.join(__dirname, "preload.cjs")
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
  win.webContents.on("did-finish-load", () => flushPendingPcap());
  win.on("closed", () => { if (mainWindow === win) mainWindow = null; });
  mainWindow = win;
}

// macOS 双击 .pcap 走 open-file；命令行参数也支持（其他平台或 dev 调试）
app.on("open-file", (event, filePath) => {
  event.preventDefault();
  if (/\.(pcap|pcapng|cap)$/i.test(filePath)) dispatchOpenPcap(filePath);
});

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
  registerIpcHandlers();
  try {
    await ensureDependencies();
    cachedLlmKey = await readLlmKeyFromKeychain();
    const { host, port } = await startApiSidecar();
    await createMainWindow(`http://${host}:${port}`);
  } catch (error) {
    console.error("Boot failed:", error);
    app.quit();
    return;
  }
  // 处理命令行带入的 pcap 路径（dev/调试或非 macOS 场景）
  for (const arg of process.argv.slice(2)) {
    if (/\.(pcap|pcapng|cap)$/i.test(arg)) dispatchOpenPcap(arg);
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
