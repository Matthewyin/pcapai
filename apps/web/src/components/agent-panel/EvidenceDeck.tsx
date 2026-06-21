/*
 * EvidenceDeck — 右栏"明细数据"section（阶段 1c 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:2393-2429 的 <section className="evidenceDeck">。
 * 8 个跳转按钮 → setDetailView,各按钮的计数从 graph 派生。
 */
import React from "react";
import type { CaseGraph, DetailView } from "../../types";

type EvidenceDeckProps = {
  graph: CaseGraph | null;
  /** 跳转到详情视图（main.tsx 的 setDetailView） */
  onSelectView: (view: DetailView) => void;
};

export function EvidenceDeck(props: EvidenceDeckProps) {
  const { graph, onSelectView } = props;
  return (
    <section className="evidenceDeck">
      <h2>明细数据</h2>
      <div className="detailLaunchGrid">
        <button onClick={() => onSelectView("path")}>
          <strong>访问路径</strong>
          <span>{graph?.path.nodes.length || 0} 个节点</span>
        </button>
        <button onClick={() => onSelectView("findings")}>
          <strong>判断结果</strong>
          <span>{graph?.findings.length || 0} 条 finding</span>
        </button>
        <button onClick={() => onSelectView("sessions")}>
          <strong>会话片段</strong>
          <span>{graph?.sessions.length || 0} 个片段</span>
        </button>
        <button onClick={() => onSelectView("links")}>
          <strong>跨节点关联</strong>
          <span>{graph?.sessionLinks.length || 0} 条关联</span>
        </button>
        <button onClick={() => onSelectView("packets")}>
          <strong>数据包</strong>
          <span>{graph?.packets.length || 0} 个包</span>
        </button>
        <button onClick={() => onSelectView("events")}>
          <strong>关键事件</strong>
          <span>{graph?.evidence.length || 0} 条证据</span>
        </button>
        <button onClick={() => onSelectView("tcp_stream")}>
          <strong>TCP 流</strong>
          <span>查看完整 TCP 会话</span>
        </button>
        <button onClick={() => onSelectView("topology")}>
          <strong>网络拓扑</strong>
          <span>{graph?.networkTopology?.devices?.length || 0} 个设备</span>
        </button>
      </div>
    </section>
  );
}
