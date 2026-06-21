/*
 * MessageList — 聊天消息流容器（阶段 1b 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:1953-2032 的 <div className="chatMessages" ref={chatMessagesRef}>。
 * - 渲染 messages → MessageBubble 列表
 * - 空态：显示"Agent 只读取当前 case graph..."占位
 * - 错误态：底部展示 llmRuntime.agent.lastError（如有）
 *
 * 滚动到顶逻辑保留在 main.tsx（chatMessagesRef + effect）。
 */
import React from "react";
import type { ChatMessage, LlmRuntimeStatus } from "../../types";
import { MessageBubble } from "./MessageBubble";

type MessageListProps = {
  messages: ChatMessage[];
  /** 复制态消息 id */
  copiedMessageId: string;
  /** LLM runtime（仅用 agent.lastError） */
  llmRuntime: LlmRuntimeStatus | null;
  /** 滚动容器的 ref（由 main.tsx 持有，effect 自动 scrollTop） */
  containerRef?: React.Ref<HTMLDivElement>;

  onCopy: (message: ChatMessage) => void;
  onOpenEvidence: (message: ChatMessage, stepIndex?: number) => void;
  onSelectQuestion: (question: string) => void;
};

export function MessageList(props: MessageListProps) {
  const { messages, copiedMessageId, llmRuntime, containerRef, onCopy, onOpenEvidence, onSelectQuestion } = props;
  const hasMessages = messages.length > 0;
  const lastError = llmRuntime?.agent.lastError;

  return (
    <div className="chatMessages" ref={containerRef}>
      {hasMessages ? (
        messages.map((message) => (
          <MessageBubble
            key={message.id}
            message={message}
            copiedMessageId={copiedMessageId}
            onCopy={onCopy}
            onOpenEvidence={onOpenEvidence}
            onSelectQuestion={onSelectQuestion}
          />
        ))
      ) : (
        <article className="chatBubble assistantBubble">
          <strong>Agent</strong>
          <p>Agent 只读取当前 case graph，不直接解析 pcap。选择模型和深度后，可以直接询问当前访问链路的问题。</p>
        </article>
      )}
      {lastError ? (
        <article className="chatBubble errorBubble">
          <strong>最近错误</strong>
          <p>{lastError}</p>
        </article>
      ) : null}
    </div>
  );
}
