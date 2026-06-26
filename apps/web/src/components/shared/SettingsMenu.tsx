/*
 * SettingsMenu — 设置页右侧菜单（竖排按钮列表，渲染到 AppShell 右栏）。
 *
 * 四个配置分类：LLM / MCP / Skills / RFC，垂直排列。
 */
import React from "react";
import { useUIStore } from "../../store/useUIStore";
import type { SettingsTab } from "../../store/useUIStore";

const tabs: Array<{ id: SettingsTab; label: string }> = [
  { id: "llm", label: "LLM 配置" },
  { id: "mcp", label: "MCP Server" },
  { id: "skills", label: "Skills" },
  { id: "rfc", label: "RFC 知识库" },
];

export function SettingsMenu() {
  const settingsTab = useUIStore((s) => s.settingsTab);
  const setSettingsTab = useUIStore((s) => s.setSettingsTab);
  return (
    <aside className="settingsMenuVertical">
      <div className="settingsMenuTitle">配置</div>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          className={`settingsMenuVerticalBtn ${settingsTab === tab.id ? "active" : ""}`}
          onClick={() => setSettingsTab(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </aside>
  );
}
