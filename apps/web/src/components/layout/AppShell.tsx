/*
 * AppShell — 三栏容器（左历史 / 中交互 / 右 Agent 个性化）。
 *
 * 阶段 2 三栏新 UI 第 1 步：替换 main.tsx 的 `<section className="appShell">` grid 布局
 * 为 flex 布局 + 拖拽手柄。
 *
 * 设计取自 docs/ui-design/three-column-light.html：
 *   <div class="app" style="display:flex;height:100vh">
 *     <aside class="sidebar" />            ← sidebar slot
 *     <div class="resizer" />              ← 左/中分隔
 *     <main class="main" flex:1 />         ← children（中栏，含 page 分发）
 *     <div class="resizer" />              ← 中/右分隔（仅 agentPanel 存在时渲染）
 *     <aside class="agent-panel" />        ← agentPanel slot
 *   </div>
 *
 * 宽度来源：useUIStore（sidebarWidth / agentPanelWidth），persist 到 localStorage["pcapai-ui"]。
 * 拖拽：
 *   - 拖拽中用本地 state 实时渲染（避免高频写 localStorage）
 *   - mouseup 才写 store 落库
 *   - clamp 由 store setter 处理（SIDEBAR_MIN/MAX、AGENT_PANEL_MIN/MAX）
 *
 * 本组件只负责布局壳，不关心 children 内容。
 * agentPanel 传 null 时不渲染右栏（非 workbench 页面：history/settings/help/knowledge）。
 */
import React from "react";
import { Resizer } from "./Resizer";
import {
  useUIStore,
  SIDEBAR_MIN,
  SIDEBAR_MAX,
  AGENT_PANEL_MIN,
  AGENT_PANEL_MAX,
} from "../../store/useUIStore";

type AppShellProps = {
  /** 左栏：历史会话列表 + 设置入口（Sidebar 组件） */
  sidebar: React.ReactNode;
  /** 中栏：page 分发后的内容（workbench / history / settings / help / knowledge） */
  children: React.ReactNode;
  /** 右栏：Agent 个性化面板（insightDock / 三 Tab）；传 null 则隐藏右栏（非 workbench 页面） */
  agentPanel?: React.ReactNode;
};

export function AppShell({ sidebar, children, agentPanel }: AppShellProps) {
  // 初始宽度从 store 读（已 persist）
  const storeSidebarWidth = useUIStore((s) => s.sidebarWidth);
  const storeAgentPanelWidth = useUIStore((s) => s.agentPanelWidth);
  const setSidebarWidth = useUIStore((s) => s.setSidebarWidth);
  const setAgentPanelWidth = useUIStore((s) => s.setAgentPanelWidth);

  // 拖拽中本地 state（实时更新，mouseup 才落库 store）
  const [sidebarWidth, setSidebarWidthLocal] = React.useState(storeSidebarWidth);
  const [agentPanelWidth, setAgentPanelWidthLocal] = React.useState(storeAgentPanelWidth);

  // store 变化（如外部重置）同步到本地
  React.useEffect(() => setSidebarWidthLocal(storeSidebarWidth), [storeSidebarWidth]);
  React.useEffect(() => setAgentPanelWidthLocal(storeAgentPanelWidth), [storeAgentPanelWidth]);

  // 拖拽中本地 clamp（store setter 的 mirror，避免拖拽瞬间越界）
  const clampSidebar = (w: number) => Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, w));
  const clampAgent = (w: number) => Math.min(AGENT_PANEL_MAX, Math.max(AGENT_PANEL_MIN, w));

  const hasAgentPanel = agentPanel !== null && agentPanel !== undefined;

  return (
    <section className={`appShell ${hasAgentPanel ? "" : "appShellTwoCol"}`}>
      <aside className="appShellCol appSidebarWrap" style={{ width: sidebarWidth, flexShrink: 0 }}>
        {sidebar}
      </aside>

      <Resizer
        direction={1}
        getWidth={() => sidebarWidth}
        onDrag={(w) => setSidebarWidthLocal(clampSidebar(w))}
        onCommit={(w) => setSidebarWidth(w)}
      />

      <section className="appShellCol appContent">{children}</section>

      {hasAgentPanel ? (
        <>
          <Resizer
            direction={-1}
            getWidth={() => agentPanelWidth}
            onDrag={(w) => setAgentPanelWidthLocal(clampAgent(w))}
            onCommit={(w) => setAgentPanelWidth(w)}
          />
          <aside
            className="appShellCol appAgentPanel"
            style={{ width: agentPanelWidth, flexShrink: 0 }}
          >
            {agentPanel}
          </aside>
        </>
      ) : null}
    </section>
  );
}
