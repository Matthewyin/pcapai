/*
 * RootCauseCard — 根因卡片（阶段 2d）。
 *
 * 防幻觉边界的可视化：根据 rfcVerified 区分"RFC 验证结论"与"经验推测"。
 *   - rfcVerified=true:  绿色左边框 + "RFC 验证" 标签（高可信）
 *   - rfcVerified=false: 琥珀色左边框 + "经验推测" 标签（需人工核实）
 *
 * 设计取自 docs/ui-design/diagnosis-card-prototype.html 的 .rootcause-card / .rc-verified / .rc-speculative。
 * 亮色主题调色（阶段 2d）：用 --rc-verified-* / --rc-spec-* 语义色变量（styles.css 定义）。
 */
import React from "react";
import { BookOpen, FlaskConical } from "lucide-react";
import type { RootCauseEntry } from "../../types";

const CONFIDENCE_LABEL: Record<RootCauseEntry["confidence"], string> = {
  certain: "确定",
  high: "高置信",
  low: "低置信",
  needs_context: "需补充上下文",
};

export function RootCauseCard({ cause }: { cause: RootCauseEntry }) {
  const verified = cause.rfcVerified;
  return (
    <article className={`rootCauseCard ${verified ? "rcVerified" : "rcSpec"}`}>
      <div className="rcHeader">
        <span className={`rcTag ${verified ? "rcTagVerified" : "rcTagSpec"}`}>
          {verified ? <BookOpen size={11} /> : <FlaskConical size={11} />}
          {verified ? "RFC 验证" : "经验推测"}
        </span>
        <span className="rcConfidence">{CONFIDENCE_LABEL[cause.confidence]}</span>
      </div>
      <p className="rcCause">{cause.description}</p>
      {cause.rfcSection ? (
        <span className={`rfcChip ${verified ? "rfcChipVerified" : "rfcChipSpec"}`}>
          {cause.rfcSection}
        </span>
      ) : null}
      {(cause.evidenceCardIds.length > 0 || cause.packetIds.length > 0) && (
        <div className="rcEvidence">
          {cause.evidenceCardIds.length > 0 ? <span>证据 {cause.evidenceCardIds.length}</span> : null}
          {cause.packetIds.length > 0 ? <span>包 {cause.packetIds.length}</span> : null}
        </div>
      )}
    </article>
  );
}

/**
 * 根因列表容器（含标题）。无根因时不渲染。
 */
export function RootCauseList({ causes }: { causes: RootCauseEntry[] }) {
  if (!causes.length) return null;
  const verifiedCount = causes.filter((c) => c.rfcVerified).length;
  return (
    <section className="rootCauseSection">
      <div className="panelSectionTitle">
        <h2>根因结论</h2>
        <span className="rcSummary">
          {causes.length} 条（{verifiedCount} 已验证 / {causes.length - verifiedCount} 推测）
        </span>
      </div>
      {causes.map((cause) => (
        <RootCauseCard key={cause.id} cause={cause} />
      ))}
    </section>
  );
}

/**
 * 飞轮反馈入口（verify/dispute）。
 * 取自 docs/ui-design/three-column-light.html 的 .flywheel。
 */
export function Flywheel({ onAction }: { onAction?: (action: "verify" | "dispute") => void }) {
  const [submitted, setSubmitted] = React.useState<"verify" | "dispute" | null>(null);
  const handle = (action: "verify" | "dispute") => {
    setSubmitted(action);
    onAction?.(action);
  };
  return (
    <section className="flywheel">
      {submitted ? (
        <p className="flywheelDone">
          {submitted === "verify" ? "✓ 已记录：诊断正确，将沉淀为实战经验。" : "✗ 已记录：诊断有误，感谢纠正。"}
        </p>
      ) : (
        <>
          <p className="fwQuestion">这个诊断结论对你有帮助吗？</p>
          <div className="flywheelBtns">
            <button type="button" className="fwBtn fwYes" onClick={() => handle("verify")}>
              ✓ 正确，沉淀
            </button>
            <button type="button" className="fwBtn fwNo" onClick={() => handle("dispute")}>
              ✗ 不对，纠正
            </button>
          </div>
        </>
      )}
    </section>
  );
}
