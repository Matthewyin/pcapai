/*
 * MessageBubble — 单条聊天消息渲染（阶段 1b 从 main.tsx 抽出）。
 *
 * 行为完全等价于原 main.tsx:1955-2019 的 <article className="chatBubble ...">。
 * 约束 #1：只展示，不处理 SSE/发送。所有交互通过 callback 上抛。
 */
import React from "react";
import { Copy } from "lucide-react";
import type { ChatMessage } from "../../types";
import { renderMarkdown, displayThoughts } from "../../lib/markdown";

// token 数格式化：1234 → "1.2k"，<1000 原样
function formatTokens(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k`;
  return String(n);
}

type MessageBubbleProps = {
  message: ChatMessage;
  /** 当前复制态消息 id（用于"已复制"反馈） */
  copiedMessageId: string;
  /** 复制消息内容（main.tsx 的 copyMessage） */
  onCopy: (message: ChatMessage) => void;
  /** 打开证据详情（main.tsx 的 openEvidenceDetail）；stepIndex 仅 stepEvidence 用 */
  onOpenEvidence: (message: ChatMessage, stepIndex?: number) => void;
  /** 选中追问/建议查询（main.tsx 里 setQuestion） */
  onSelectQuestion: (question: string) => void;
};

export function MessageBubble(props: MessageBubbleProps) {
  const { message, copiedMessageId, onCopy, onOpenEvidence, onSelectQuestion } = props;
  const thoughts = displayThoughts(message);
  const hasStepEvidence = message.role === "assistant" && message.stepEvidence && Object.keys(message.stepEvidence).length > 0;
  // 助手消息且已完成且有内容 → Markdown 渲染；否则纯文本
  const showMarkdown = message.role === "assistant" && !message.streaming && !!message.content;
  const showEvidenceLink = message.role === "assistant" && !message.streaming && !!message.evidenceCards?.length;
  const showHypotheses = message.role === "assistant" && !message.streaming && !!message.hypotheses?.length;
  const showFollowUps = message.role === "assistant" && !message.streaming && !!message.followUpQuestions?.length;

  return (
    <article className={`chatBubble ${message.role === "user" ? "userBubble" : "assistantBubble"}`}>
      <div className="chatBubbleHeader">
        <strong>
          {message.role === "user" ? "你" : "Agent"}
          {message.streaming ? " 正在输出..." : ""}
        </strong>
        <div className="chatBubbleHeaderRight">
          {message.usage ? (
            <span className="usageBadge" title={message.usage.model ? `模型：${message.usage.model}` : undefined}>
              <span className="usageIn">↓{formatTokens(message.usage.inputTokens)}</span>
              <span className="usageOut">↑{formatTokens(message.usage.outputTokens)}</span>
              <span className="usageTotal">共{formatTokens(message.usage.totalTokens)}</span>
            </span>
          ) : null}
          <button className="copyButton" onClick={() => onCopy(message)} type="button">
            <Copy size={14} />
            {copiedMessageId === message.id ? "已复制" : "复制"}
          </button>
        </div>
      </div>

      {thoughts.length ? (
        <details className="thoughtBox" open>
          <summary>执行轨迹</summary>
          <ol>
            {thoughts.map((thought, index) => (
              <li key={`${message.id}-thought-${index}`}>{thought}</li>
            ))}
          </ol>
        </details>
      ) : null}

      {hasStepEvidence ? (
        <div className="stepEvidenceLinks">
          {Object.entries(message.stepEvidence!).map(([idx, step]) =>
            step.evidenceCards.length ? (
              <div key={`${message.id}-se-${idx}`} className="stepEvidenceLink">
                <span className="stepEvidenceLabel">步骤 {Number(idx) + 1}：{step.purpose}</span>
                <button type="button" onClick={() => onOpenEvidence(message, Number(idx))}>
                  {step.evidenceCards.length} 张卡片
                </button>
              </div>
            ) : null
          )}
        </div>
      ) : null}

      {showMarkdown ? (
        <div className="markdownBody" dangerouslySetInnerHTML={{ __html: renderMarkdown(message.content) }} />
      ) : (
        <p>{message.content || (message.streaming ? "等待模型返回..." : "")}</p>
      )}

      {showEvidenceLink ? (
        <div className="evidenceRefLink">
          <button type="button" onClick={() => onOpenEvidence(message)}>
            查看证据详情（{message.evidenceCards!.length} 张卡片）
          </button>
        </div>
      ) : null}

      {showHypotheses ? (
        <div className="hypothesesPanel">
          <div className="hypothesesTitle">假设验证进度</div>
          {message.hypotheses!.map((h, index) => (
            <div key={`${message.id}-h-${index}`} className={`hypothesisItem hypothesis-${h.status}`}>
              <span className="hypothesisStatus">
                {h.status === "confirmed" ? "✓" : h.status === "ruled_out" ? "✗" : h.status === "testing" ? "◎" : "○"}
              </span>
              <span className="hypothesisDesc">{h.description}</span>
            </div>
          ))}
        </div>
      ) : null}

      {showFollowUps ? (
        <div className="followUpQuestions">
          <div className="followUpTitle">你可以回答：</div>
          {message.followUpQuestions!.map((q, index) => (
            <button type="button" className="followUpButton" key={`${message.id}-fq-${index}`} onClick={() => onSelectQuestion(q)}>
              {q}
            </button>
          ))}
        </div>
      ) : null}

      {message.suggestedQueries?.length ? (
        <div className="suggestedQueries">
          {message.suggestedQueries.map((sq, index) => (
            <button
              type="button"
              className="suggestedQuery"
              key={`${message.id}-sq-${index}`}
              title={sq.reason}
              onClick={() => onSelectQuestion(sq.question)}
            >
              {sq.question}
            </button>
          ))}
        </div>
      ) : null}
    </article>
  );
}
