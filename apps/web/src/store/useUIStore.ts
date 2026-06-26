/*
 * useUIStore — 全局 UI 状态：页面切换 / 主题 / 三栏布局。
 *
 * 阶段 0：骨架。当前 main.tsx 仍用本地 useState，这里只是占位 + 后续组件迁移目标。
 *
 * 迁移映射（main.tsx → store）：
 *   page / setPage           → page / setPage
 *   theme / setTheme         → theme / setTheme
 *   detailView / setDetailView → detailView / setDetailView
 *
 * 三栏宽度（左历史/右 Agent）目前 main.tsx 是 CSS 写死的；阶段 1 拆 Sidebar/AgentPanel 时
 * 会引入 sidebarWidth / agentPanelWidth + 拖拽，min/max 约束来自交接文档（180-320 / 280-480）。
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { DetailView } from "../types";

export type Page = "workbench" | "history" | "settings" | "help" | "knowledge";
export type Theme = "dark" | "light";
export type SettingsTab = "llm" | "mcp" | "skills" | "rfc";

// 三栏宽度约束（来自交接文档约束 #4）
export const SIDEBAR_MIN = 180;
export const SIDEBAR_MAX = 320;
export const AGENT_PANEL_MIN = 280;
export const AGENT_PANEL_MAX = 480;
export const SIDEBAR_DEFAULT = 240;
export const AGENT_PANEL_DEFAULT = 360;

type UIState = {
  /** 顶部路由：工作台/历史/设置/帮助/知识库 */
  page: Page;
  /** 主题（约束 #2：仅亮色，但保留 dark 用于切换前的兼容） */
  theme: Theme;
  /** 详情视图模式（path/findings/sessions/...） */
  detailView: DetailView | null;

  /** 三栏宽度（拖拽调整，localStorage 持久化） */
  sidebarWidth: number;
  agentPanelWidth: number;
  /** 左右栏折叠态（true=隐藏）。折叠按钮在栏顶部，展开按钮浮在边缘 */
  sidebarCollapsed: boolean;
  agentPanelCollapsed: boolean;
  /** 设置页当前选中的配置 tab（LLM/MCP/Skills/RFC） */
  settingsTab: SettingsTab;

  setPage: (page: Page) => void;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  setDetailView: (view: DetailView | null) => void;
  setSidebarWidth: (width: number) => void;
  setAgentPanelWidth: (width: number) => void;
  toggleSidebar: () => void;
  toggleAgentPanel: () => void;
  setSettingsTab: (tab: SettingsTab) => void;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

export const useUIStore = create<UIState>()(
  persist(
    (set, get) => ({
      page: "workbench",
      // 默认亮色（约束 #2：仅亮色主题）。原 main.tsx 读 localStorage 'pcapai-theme'
      theme: "light",
      detailView: null,
      sidebarWidth: SIDEBAR_DEFAULT,
      agentPanelWidth: AGENT_PANEL_DEFAULT,
      sidebarCollapsed: false,
      agentPanelCollapsed: false,
      settingsTab: "llm",

      setPage: (page) => set({ page }),
      setTheme: (theme) => set({ theme }),
      toggleTheme: () => set({ theme: get().theme === "dark" ? "light" : "dark" }),
      setDetailView: (detailView) => set({ detailView }),
      setSidebarWidth: (width) => set({ sidebarWidth: clamp(width, SIDEBAR_MIN, SIDEBAR_MAX) }),
      setAgentPanelWidth: (width) => set({ agentPanelWidth: clamp(width, AGENT_PANEL_MIN, AGENT_PANEL_MAX) }),
      toggleSidebar: () => set({ sidebarCollapsed: !get().sidebarCollapsed }),
      toggleAgentPanel: () => set({ agentPanelCollapsed: !get().agentPanelCollapsed }),
      setSettingsTab: (settingsTab) => set({ settingsTab })
    }),
    {
      name: "pcapai-ui",
      // 只持久化需要跨会话保留的字段
      partialize: (state) => ({
        theme: state.theme,
        sidebarWidth: state.sidebarWidth,
        agentPanelWidth: state.agentPanelWidth,
        sidebarCollapsed: state.sidebarCollapsed,
        agentPanelCollapsed: state.agentPanelCollapsed
      })
    }
  )
);
