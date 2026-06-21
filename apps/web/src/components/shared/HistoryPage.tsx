/*
 * HistoryPage — 历史案例管理页（阶段 1d 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:1512-1539 的 <section className="historyPage">。
 * 批量选择/全选/清空/删除 + 卡片点击进入案例。
 */
import React from "react";
import { Trash2 } from "lucide-react";
import type { CaseSummary } from "../../types";

type HistoryPageProps = {
  caseHistory: CaseSummary[];
  selectedCaseIds: string[];

  onToggleSelect: (caseId: string) => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  onDeleteSelected: () => void;
  onOpenCase: (caseId: string) => void;
};

export function HistoryPage(props: HistoryPageProps) {
  const { caseHistory, selectedCaseIds, onToggleSelect, onSelectAll, onClearSelection, onDeleteSelected, onOpenCase } = props;

  return (
    <section className="historyPage">
      <section className="historyToolbar">
        <div>
          <h2>历史案例管理</h2>
          <p>这里集中处理历史案例的批量选择和删除。左侧边栏只用于快速进入案例。</p>
        </div>
        <div className="bulkActions">
          <button onClick={onSelectAll} disabled={!caseHistory.length}>全选</button>
          <button onClick={onClearSelection} disabled={!selectedCaseIds.length}>清空</button>
          <button className="danger" onClick={onDeleteSelected} disabled={!selectedCaseIds.length}>
            <Trash2 size={16} /> 删除
          </button>
        </div>
      </section>
      <section className="historyGrid">
        {caseHistory.map((item) => (
          <article className="historyCard" key={item.caseId}>
            <input
              type="checkbox"
              checked={selectedCaseIds.includes(item.caseId)}
              onChange={() => onToggleSelect(item.caseId)}
              aria-label={`选择 ${item.title}`}
            />
            <button onClick={() => onOpenCase(item.caseId)}>
              <strong>{item.title}</strong>
              <span>{item.captureCount} 节点 / {item.rawPacketCount} 捕获包 / {item.packetCount} 样本包</span>
              <small>{item.runCount} 个分析版本 / {item.findingCount} 条判断</small>
            </button>
          </article>
        ))}
        {!caseHistory.length && <div className="empty">暂无历史案例。</div>}
      </section>
    </section>
  );
}
