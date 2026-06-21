/*
 * useChatStore — 中栏聊天状态：消息流 / SSE 流式回答 / 输入框 / composer 抓包。
 *
 * 阶段 0：骨架。当前 main.tsx 仍用本地 useState + ask() 闭包，本 store 是后续拆 ChatPanel
 * （阶段 1b）时的迁移目标。**约束 #1：聊天输入框和交互框不动** —— 迁移时只把状态搬过来，
 * ask/SSE 逻辑保持不变。
 *
 * 迁移映射（main.tsx → store）：
 *   chatMessages / setChatMessages      → messages / setMessages
 *   answer / setAnswer                  → streamingAnswer / setStreamingAnswer
 *   question / setQuestion              → question / setQuestion
 *   status / setStatus                  → status / setStatus
 *   isAsking / setIsAsking              → isAsking / setIsAsking
 *   report / setReport                  → report / setReport
 *   composerFiles / setComposerFiles    → composerFiles / setComposerFiles
 *   composerExpanded / setComposerExpanded → composerExpanded / ...
 *   dragActive / setDragActive          → dragActive / ...
 *   copiedMessageId / setCopiedMessageId → copiedMessageId / ...
 *   chatProfileId / setChatProfileId    → chatProfileId / ...（CHAT_PROFILE_ID_KEY）
 *   thinkingDepth / reasoningDepth      → 模型行为深度选择（localStorage）
 *
 * SSE 接收（main.tsx:1082 ask / 1157-1209 流读取）逻辑保留在 ChatPanel 组件内，
 * 通过 setMessages / setStreamingAnswer 写入本 store。
 */
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { ChatMessage } from "../types";

const CHAT_PROFILE_ID_KEY = "pcapai-chat-profile-id";
const THINKING_DEPTH_KEY = "pcapai-thinking-depth";
const REASONING_DEPTH_KEY = "pcapai-reasoning-depth";

export const THINKING_DEPTHS = ["简洁", "标准", "深入"] as const;
export const REASONING_DEPTHS = ["快速", "标准", "推理"] as const;
export type ThinkingDepth = (typeof THINKING_DEPTHS)[number];
export type ReasoningDepth = (typeof REASONING_DEPTHS)[number];

type ChatState = {
  /** 消息流（含 user / assistant，按时间顺序） */
  messages: ChatMessage[];
  /** SSE 流式输出中累积的回答文本（message 落地前） */
  streamingAnswer: string;
  /** 输入框当前内容 */
  question: string;
  /** 顶部状态提示（如"请先新建案例"） */
  status: string;
  /** 是否正在等待 Agent 回答 */
  isAsking: boolean;
  /** Markdown 报告（导出用） */
  report: string;

  /** composer 待上传文件 */
  composerFiles: File[];
  composerExpanded: boolean;
  dragActive: boolean;

  /** 复制按钮反馈 */
  copiedMessageId: string;

  /** 模型行为选择（持久化） */
  chatProfileId: string;
  thinkingDepth: ThinkingDepth;
  reasoningDepth: ReasoningDepth;

  setMessages: (messages: ChatMessage[] | ((prev: ChatMessage[]) => ChatMessage[])) => void;
  setStreamingAnswer: (answer: string) => void;
  setQuestion: (question: string) => void;
  setStatus: (status: string) => void;
  setIsAsking: (asking: boolean) => void;
  setReport: (report: string) => void;
  setComposerFiles: (files: File[] | ((prev: File[]) => File[])) => void;
  setComposerExpanded: (expanded: boolean) => void;
  setDragActive: (active: boolean) => void;
  setCopiedMessageId: (id: string) => void;
  setChatProfileId: (id: string) => void;
  setThinkingDepth: (depth: ThinkingDepth) => void;
  setReasoningDepth: (depth: ReasoningDepth) => void;
  reset: () => void;
};

const initialPersisted = {
  chatProfileId: localStorage.getItem(CHAT_PROFILE_ID_KEY) ?? "",
  thinkingDepth: "标准" as ThinkingDepth,
  reasoningDepth: "标准" as ReasoningDepth
};

export const useChatStore = create<ChatState>()(
  persist(
    (set) => ({
      messages: [],
      streamingAnswer: "",
      question: "",
      status: "请先新建案例，再上传 pcap。",
      isAsking: false,
      report: "",
      composerFiles: [],
      composerExpanded: false,
      dragActive: false,
      copiedMessageId: "",
      ...initialPersisted,

      setMessages: (updater) =>
        set((state) => ({
          messages: typeof updater === "function" ? updater(state.messages) : updater
        })),
      setStreamingAnswer: (streamingAnswer) => set({ streamingAnswer }),
      setQuestion: (question) => set({ question }),
      setStatus: (status) => set({ status }),
      setIsAsking: (isAsking) => set({ isAsking }),
      setReport: (report) => set({ report }),
      setComposerFiles: (updater) =>
        set((state) => ({
          composerFiles: typeof updater === "function" ? updater(state.composerFiles) : updater
        })),
      setComposerExpanded: (composerExpanded) => set({ composerExpanded }),
      setDragActive: (dragActive) => set({ dragActive }),
      setCopiedMessageId: (copiedMessageId) => set({ copiedMessageId }),
      setChatProfileId: (chatProfileId) => set({ chatProfileId }),
      setThinkingDepth: (thinkingDepth) => set({ thinkingDepth }),
      setReasoningDepth: (reasoningDepth) => set({ reasoningDepth }),
      reset: () =>
        set({
          messages: [],
          streamingAnswer: "",
          question: "",
          isAsking: false,
          report: "",
          composerFiles: []
        })
    }),
    {
      name: "pcapai-chat",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        chatProfileId: state.chatProfileId,
        thinkingDepth: state.thinkingDepth,
        reasoningDepth: state.reasoningDepth
      })
    }
  )
);
