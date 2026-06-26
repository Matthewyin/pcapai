// 最小桥：暴露安全的 IPC 接口给前端，避免污染全局
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("pcapaiDesktop", {
  // LLM key 与其他敏感配置走 Keychain；前端不再写 .env
  secrets: {
    getLlmKey: () => ipcRenderer.invoke("pcapai:secrets:get-llm-key"),
    setLlmKey: (value) => ipcRenderer.invoke("pcapai:secrets:set-llm-key", value),
    clearLlmKey: () => ipcRenderer.invoke("pcapai:secrets:clear-llm-key")
  },
  // 选择目录（Electron dialog.showOpenDialog）
  selectDirectory: () => ipcRenderer.invoke("pcapai:select-directory"),
  // 让前端知道当前在 Electron 容器内，可启用 desktop-only 特性
  isDesktop: true,
  platform: process.platform
});
