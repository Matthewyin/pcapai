// Electron 主进程：以 sidecar 子进程方式启动 Express API、隔离 userData 数据目录、托管主窗口。
// 开发模式：API 子进程走 tsx，窗口加载 Vite dev server（30023）。
// 生产模式：API 子进程走 node + 编译产物，窗口加载 apps/web/dist。
import { app, BrowserWindow, dialog, ipcMain, Menu, shell } from "electron";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import path from "node:path";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

// macOS 上 Wireshark.app 的 CLI 工具目录（GUI app 启动时 PATH 不含此路径,需显式探测）
const WIRESHARK_APP_MACOS_DIR = "/Applications/Wireshark.app/Contents/MacOS";
const WIRESHARK_APP_PATH = "/Applications/Wireshark.app";

/**
 * 探测单个 CLI 工具的绝对路径。
 * 顺序：(1) which（PATH 解析,开发模式或 brew symlink 时命中）
 *       (2) Wireshark.app/Contents/MacOS/<tool>（GUI app 默认安装位置）
 *       (3) /opt/homebrew/bin/<tool> + /usr/local/bin/<tool>（brew --cask 装的 symlink）
 * 找不到返回 null。
 */
function resolveCliTool(tool: string): string | null {
  // (1) which
  const whichResult = spawnSync("which", [tool], { stdio: ["ignore", "pipe", "ignore"] });
  if (whichResult.status === 0) {
    const found = String(whichResult.stdout).trim();
    if (found) return found;
  }
  // (2) Wireshark.app/Contents/MacOS/
  const appPath = path.join(WIRESHARK_APP_MACOS_DIR, tool);
  if (existsSync(appPath)) return appPath;
  // (3) brew 常见 symlink 位置
  for (const binDir of ["/opt/homebrew/bin", "/usr/local/bin"]) {
    const brewPath = path.join(binDir, tool);
    if (existsSync(brewPath)) return brewPath;
  }
  return null;
}

/** 解析全部 CLI 工具路径（供 buildSidecarEnv 注入）。Wireshark GUI 单独处理（.app 可直接 open）。 */
function resolveCliToolPaths(): { tshark: string | null; editcap: string | null; capinfos: string | null; wireshark: string | null } {
  return {
    tshark: resolveCliTool("tshark"),
    editcap: resolveCliTool("editcap"),
    capinfos: resolveCliTool("capinfos"),
    wireshark: existsSync(WIRESHARK_APP_PATH) ? WIRESHARK_APP_PATH : resolveCliTool("wireshark")
  };
}

// 系统依赖检测：tshark 套件是硬依赖（解析数据包），Wireshark.app 仅用于复核证据（软依赖）
function checkSystemDependencies(): { ok: boolean; missing: string[]; paths: ReturnType<typeof resolveCliToolPaths> } {
  const paths = resolveCliToolPaths();
  const missing: string[] = [];
  // CLI 工具缺失则阻断（核心解析能力）
  if (!paths.tshark) missing.push("tshark");
  if (!paths.editcap) missing.push("editcap");
  if (!paths.capinfos) missing.push("capinfos");
  // Wireshark.app 缺失只警告
  if (!paths.wireshark) missing.push("Wireshark.app（用于复核证据）");
  const blocking = !paths.tshark || !paths.editcap || !paths.capinfos;
  return { ok: !blocking, missing, paths };
}

// 解析到的 CLI 工具绝对路径（ensureDependencies 填充,buildSidecarEnv 读取注入）
let resolvedToolPaths: ReturnType<typeof resolveCliToolPaths> | null = null;

async function ensureDependencies() {
  const { ok, missing, paths } = checkSystemDependencies();
  resolvedToolPaths = paths;
  if (!missing.length) return;
  const result = await dialog.showMessageBox({
    type: ok ? "warning" : "error",
    title: ok ? "建议安装" : "缺少系统依赖",
    message: ok ? "未检测到 Wireshark.app，证据复核功能将不可用。" : "pcapAI 需要 Wireshark 套件提供的命令才能解析数据包。",
    detail: `检测缺失：${missing.join("、")}\n\n推荐方案：访问 https://www.wireshark.org/download.html 下载安装；或在终端执行：\n  brew install --cask wireshark\n安装完成后重新启动 pcapAI。`,
    buttons: ok ? ["前往下载", "继续"] : ["前往下载", "退出"],
    defaultId: 0,
    cancelId: 1
  });
  if (result.response === 0) await shell.openExternal("https://www.wireshark.org/download.html");
  if (!ok) {
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
  // 目录选择器（设置页 Skills 目录选择）
  ipcMain.handle("pcapai:select-directory", async () => {
    const win = BrowserWindow.getFocusedWindow();
    if (!win) return null;
    const result = await dialog.showOpenDialog(win, {
      properties: ["openDirectory"],
      title: "选择 Skills 目录"
    });
    if (result.canceled || !result.filePaths.length) return null;
    return result.filePaths[0];
  });
}

function buildSidecarEnv() {
  const userData = app.getPath("userData");
  // userData 可写区：cases / rfc-index（完整库下载目标）/ field-notes / skills
  const dirs = {
    cases: path.join(userData, "cases"),
    rfcIndex: path.join(userData, "rfc-index"),
    fieldNotes: path.join(userData, "field-notes"),
    fieldNotesSeeds: path.join(userData, "field-notes", "seeds"),
    skills: path.join(userData, "skills")
  };
  for (const dir of Object.values(dirs)) mkdirSync(dir, { recursive: true });

  // 首次启动：从 Resources（只读）seed userData 可写区（field-notes seeds + skills）
  // 后续用户可自由编辑/新增，不受 app 更新覆盖
  seedUserDataFromResources(dirs);

  const env: NodeJS.ProcessEnv = { ...process.env, PCAPAI_ROOT: workspaceRoot };
  // Keychain 中的 LLM Key 在 spawn 前注入；优先于 .env 文件（API 读 process.env）
  if (cachedLlmKey) env.PCAPAI_LLM_API_KEY = cachedLlmKey;
  if (!isDev) {
    // 生产期 sidecar 与其 spawn 的 MCP 子进程都用 Electron 二进制当 node 运行时，
    // 必须设此变量让 execPath 以纯 node 模式启动（否则会拉起 GUI 实例）。
    // native module（better-sqlite3 / keytar）均为 N-API，Electron ABI 130 下实测可加载。
    env.ELECTRON_RUN_AS_NODE = "1";
    env.PCAPAI_CASE_DATA_DIR ??= dirs.cases;
    // 阶段 3a 双层库：
    //   - 完整库（userData 可写，下载目标）：PCAPAI_RAG_INDEX_PATH → userData/rfc-index/rfc.db
    //   - 精简库（Resources 只读，降级层）：PCAPAI_RAG_CURATED_INDEX_PATH → Resources/data/rfc-index/rfc-mini.db
    env.PCAPAI_RAG_INDEX_PATH ??= path.join(dirs.rfcIndex, "rfc.db");
    const bundledMini = path.join(workspaceRoot, "data/rfc-index/rfc-mini.db");
    if (existsSync(bundledMini)) env.PCAPAI_RAG_CURATED_INDEX_PATH ??= bundledMini;
    // 完整库下载服务目标（rfcDownloadService 读此变量）
    env.PCAPAI_USERDATA_DIR ??= userData;
    env.PCAPAI_LEARNED_PATTERNS_PATH ??= path.join(userData, "learned_patterns.json");
    const bundledRfc = path.join(workspaceRoot, "RFC");
    if (existsSync(bundledRfc)) env.PCAPAI_RAG_RFC_DIR ??= bundledRfc;
    // 阶段 3 实战笔记 + 技能：指向 userData 可写区（首次启动已从 Resources seed）
    env.PCAPAI_FIELD_NOTES_SEEDS_DIR ??= dirs.fieldNotesSeeds;
    env.PCAPAI_FIELD_NOTES_INDEX_PATH ??= path.join(dirs.fieldNotes, "field-notes.db");
    env.PCAPAI_SKILLS_DIR ??= dirs.skills;
    // 生产模式：API sidecar 同源托管前端 dist（/api + 静态文件同端口）
    // 这样 Electron 窗口用 loadURL(apiUrl) 加载,fetch("/api/*") 天然同源,无需路径重写
    env.PCAPAI_SERVE_WEB ??= "1";
    env.PCAPAI_WEB_DIST_PATH ??= path.join(workspaceRoot, "apps/web/dist");
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
  // CLI 工具路径注入（开发 + 生产都需要：GUI app 启动时 PATH 不含 Wireshark.app/Contents/MacOS）
  // ensureDependencies 已探测到绝对路径,这里注入给 API + MCP 子进程,避免裸命令名 PATH 解析失败
  if (resolvedToolPaths) {
    if (resolvedToolPaths.tshark) env.PCAPAI_TSHARK_COMMAND ??= resolvedToolPaths.tshark;
    if (resolvedToolPaths.editcap) env.PCAPAI_EDITCAP_COMMAND ??= resolvedToolPaths.editcap;
    if (resolvedToolPaths.capinfos) env.PCAPAI_CAPINFOS_COMMAND ??= resolvedToolPaths.capinfos;
    if (resolvedToolPaths.wireshark) env.PCAPAI_WIRESHARK_COMMAND ??= resolvedToolPaths.wireshark;
  }
  return env;
}

/**
 * 首次启动：从 Resources（只读）复制 field-notes seeds + skills 到 userData（可写）。
 * userData 目标已存在文件时不覆盖（用户已编辑过）。
 */
function seedUserDataFromResources(dirs: { fieldNotesSeeds: string; skills: string }) {
  const seedPairs: Array<[string, string]> = [
    [path.join(workspaceRoot, "data/field-notes/seeds"), dirs.fieldNotesSeeds],
    [path.join(workspaceRoot, "data/skills"), dirs.skills]
  ];
  for (const [src, dest] of seedPairs) {
    if (!existsSync(src)) continue;
    try {
      for (const entry of readdirSync(src)) {
        const srcFile = path.join(src, entry);
        const destFile = path.join(dest, entry);
        if (existsSync(destFile)) continue; // 不覆盖用户编辑
        copyFileSync(srcFile, destFile);
      }
    } catch {
      // seed 失败不阻塞启动（API 会用空库降级）
    }
  }
  // seed MCP server 注册表 + skills 目录配置（首次启动写入 userData，用户后续可编辑）
  seedPluginConfig();
}

/**
 * 首次启动 seed MCP server 注册表 + skills 目录配置到 userData。
 * 用户后续可通过设置页编辑（不覆盖已有文件）。
 */
function seedPluginConfig() {
  const userData = app.getPath("userData");
  // MCP 注册表：内置 tshark-query + evidence-opener（用 ${resources} 变量，运行时解析）
  const mcpRegPath = path.join(userData, "mcp-registries.json");
  if (!existsSync(mcpRegPath)) {
    const mcpServers = {
      servers: [
        {
          id: "tshark-query",
          name: "tshark-query（数据包查询）",
          type: "local",
          enabled: true,
          builtIn: true,
          command: process.execPath,
          args: ["${resources}/mcp/tshark-query/dist/index.js"],
          env: {}
        },
        {
          id: "evidence-opener",
          name: "Wireshark 证据打开",
          type: "local",
          enabled: true,
          builtIn: true,
          command: process.execPath,
          args: ["${resources}/mcp/evidence-opener/dist/index.js"],
          env: {}
        }
      ]
    };
    try { writeFileSync(mcpRegPath, JSON.stringify(mcpServers, null, 2), "utf8"); } catch { /* ignore */ }
  }
  // Skills 目录配置：只 seed 内置目录（只读）。userData/skills 已作为主目录（PCAPAI_SKILLS_DIR），
  // 不需要再列为额外目录（避免重复）。
  const skillsCfgPath = path.join(userData, "skills-config.json");
  if (!existsSync(skillsCfgPath)) {
    const skillsCfg = {
      directories: [
        "${resources}/data/skills"
      ]
    };
    try { writeFileSync(skillsCfgPath, JSON.stringify(skillsCfg, null, 2), "utf8"); } catch { /* ignore */ }
  }
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
  // 防止页面内意外导航（表单提交/链接点击等导致窗口跳转到未知 URL）
  win.webContents.on("will-navigate", (event, url) => {
    // 只允许同源导航（API server 内部路由），其他一律拦截
    const apiOrigin = apiUrl.replace(/\/+$/, "");
    if (!url.startsWith(apiOrigin)) {
      event.preventDefault();
      if (url.startsWith("http")) shell.openExternal(url);
    }
  });
  if (isDev) {
    const devUrl = process.env.PCAPAI_WEB_DEV_URL || "http://127.0.0.1:30023";
    await win.loadURL(devUrl);
  } else {
    // 生产模式：API sidecar 同源托管前端（PCAPAI_SERVE_WEB=1），loadURL 让 fetch("/api/*") 天然同源
    // 避免了 file:// 协议下相对路径 / API 请求 / SSE / Blob URL 的所有断裂问题
    await win.loadURL(apiUrl);
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

// 单实例锁：防止多进程同时运行（双击 app 多次 / 发送消息意外拉起新进程）
// 第二个实例启动时，聚焦已有窗口并处理命令行参数（如双击 .pcap 打开）
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on("second-instance", (_event, argv) => {
    // 聚焦已有窗口
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      if (!mainWindow.isVisible()) mainWindow.show();
      mainWindow.focus();
    }
    // 处理第二个实例带来的 pcap 路径（macOS open-file 事件已处理，这里兜底命令行参数）
    for (const arg of argv.slice(2)) {
      if (/\.(pcap|pcapng|cap)$/i.test(arg)) dispatchOpenPcap(arg);
    }
  });
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
