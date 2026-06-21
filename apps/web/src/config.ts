/**
 * API 基址解析：
 *   - 浏览器/Vite dev 模式：空字符串（fetch("/api/...") 走 Vite proxy 或同源）
 *   - Electron loadFile 模式：main.ts 注入 window.__PCAPAI_API__（如 "http://127.0.0.1:30022"）
 *     此时 fetch 必须用绝对 URL，否则 /api 会解析到 file:///api
 */
const electronApiBase = typeof window !== "undefined" ? (window as unknown as { __PCAPAI_API__?: string }).__PCAPAI_API__ : undefined;
export const apiBase = electronApiBase || "";

/**
 * Electron file:// 模式下劫持 fetch：把相对路径 /api/* 重写为绝对 URL（指向 API sidecar）。
 * dev 模式（apiBase 为空）时不干预，走 Vite proxy。
 */
if (apiBase && typeof window !== "undefined") {
  const originalFetch = globalThis.fetch;
  try {
    Object.defineProperty(globalThis, "fetch", {
      value: (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        return originalFetch(url.startsWith("/api/") ? apiBase + url : input, init);
      },
      configurable: true,
      writable: true
    });
  } catch {
    // defineProperty 失败时降级直接赋值
    globalThis.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return originalFetch(url.startsWith("/api/") ? apiBase + url : input, init);
    };
  }
}

export const webConfig = {
  defaultQuestion: __PCAPAI_WEB_CONFIG__.defaultQuestion,
  chatHistoryLimit: __PCAPAI_WEB_CONFIG__.chatHistoryLimit,
  conversationDisplayLimit: __PCAPAI_WEB_CONFIG__.conversationDisplayLimit,
  keyPacketDisplayLimit: __PCAPAI_WEB_CONFIG__.keyPacketDisplayLimit,
  groupFailureModeDisplayLimit: __PCAPAI_WEB_CONFIG__.groupFailureModeDisplayLimit
};
