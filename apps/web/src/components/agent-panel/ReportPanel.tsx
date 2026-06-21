/*
 * ReportPanel — 右栏"报告"section（阶段 1c 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:2431-2438 的 <section className="reportPanel">。
 * 只依赖：是否有 graph（决定生成按钮 disabled）+ report 文本 + 2 个 handler。
 */
import React from "react";

type ReportPanelProps = {
  /** 是否有案例（控制"生成报告"按钮 disabled） */
  hasGraph: boolean;
  /** 当前报告文本（空时显示占位说明） */
  report: string;
  /** 生成报告（main.tsx 的 exportReport） */
  onGenerate: () => void;
  /** 复制报告（main.tsx 的 copyReport） */
  onCopy: () => void;
};

export function ReportPanel(props: ReportPanelProps) {
  const { hasGraph, report, onGenerate, onCopy } = props;
  return (
    <section className="reportPanel">
      <h2>报告</h2>
      <div className="mappingActions">
        <button className="primary" onClick={onGenerate} disabled={!hasGraph}>生成报告</button>
        <button onClick={onCopy} disabled={!report}>复制报告</button>
      </div>
      <pre>{report || "报告基于当前 QueryRun、当前证据卡、选中 session 和 checks 生成，不调用大模型。"}</pre>
    </section>
  );
}
