/*
 * useAgentStore — 右栏 Agent 个性化状态：当前 Tab / 工具轨迹 / 诊断 / 根因 / 证据卡 / TCP 流。
 *
 * 阶段 0：骨架。右栏三 Tab（知识脉络/推理轨迹/诊断档案）尚未建，本 store 是阶段 1c 拆
 * AgentPanel 时的迁移目标。
 *
 * 迁移映射（main.tsx → store）：
 *   toolTraceOpen / setToolTraceOpen       → toolTraceOpen（推理轨迹折叠态）
 *   insightsOpen / setInsightsOpen         → insightsOpen（洞察面板折叠态）
 *   rightPanelHighlight / setRightPanelHighlight → rightHighlight（证据/会话高亮联动）
 *   tcpStreams / setTcpStreams             → tcpStreams（TCP 流列表）
 *   tcpStreamContent / setTcpStreamContent → tcpStreamContent（流内容）
 *   tcpStreamLoading / setTcpStreamLoading → tcpStreamLoading
 *   conversationPackets / setStatus        → conversationPackets（会话展开包列表）
 *   selectedCandidateGroupId               → 候选组选择（左→右联动）
 *
 * 右栏三 Tab 是新增的：
 *   activeTab: "knowledge" | "trace" | "diagnosis"
 *     - knowledge: 知识脉络（实战库/Skills/RFC 命中）
 *     - trace: 推理轨迹（工具调用 timeline）
 *     - diagnosis: 诊断档案（根因卡 + 证据 + 不确定性）
 *
 * 根因分层（handoff 约束 #6 + types.ts 待补的 rootCauses）：
 *   rootCauses 中每条带 rfcVerified 区分"RFC 验证结论"与"推测"，
 *   右栏卡片用 verified / speculative 颜色区分（见 tailwind.css 语义色）。
 */
import { create } from "zustand";
import type { PacketSummary, RootCauseEntry } from "../types";

export type AgentPanelTab = "knowledge" | "trace" | "diagnosis";
export type RightHighlight = "evidence" | "conversation" | "";

export type TcpStreamRow = {
  streamIndex: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  packetCount: number;
  byteCount: number;
  displayFilter: string;
};

export type TcpStreamContent = {
  clientData: string;
  serverData: string;
  streamIndex: number;
  format: string;
  totalBytes: number;
  truncated: boolean;
};

// RootCauseEntry 已迁至 types.ts（阶段 2 数据契约补全，ChatMessage.rootCauses 引用）
export type { RootCauseEntry };

type AgentState = {
  /** 当前右栏 Tab（默认诊断档案，因为是 Agent 输出最核心的） */
  activeTab: AgentPanelTab;
  /** 推理轨迹折叠态（旧 main.tsx 中工具轨迹开关） */
  toolTraceOpen: boolean;
  /** 洞察面板折叠态 */
  insightsOpen: boolean;
  /** 右栏联动高亮（点证据卡 → 高亮会话，反之亦然） */
  rightHighlight: RightHighlight;

  /** 当前回答的根因列表（区分 RFC 验证 / 推测） */
  rootCauses: RootCauseEntry[];

  /** TCP 流查看器 */
  tcpStreams: TcpStreamRow[];
  tcpStreamContent: TcpStreamContent | null;
  tcpStreamLoading: boolean;

  /** 会话展开后的包列表（中栏→右栏联动） */
  conversationPackets: PacketSummary[];
  conversationPacketsStatus: string;

  /** 候选组选择（QueryRun 左→右联动） */
  selectedCandidateGroupId: string;

  setActiveTab: (tab: AgentPanelTab) => void;
  setToolTraceOpen: (open: boolean) => void;
  setInsightsOpen: (open: boolean) => void;
  setRightHighlight: (highlight: RightHighlight) => void;
  setRootCauses: (causes: RootCauseEntry[]) => void;
  setTcpStreams: (streams: TcpStreamRow[]) => void;
  setTcpStreamContent: (content: TcpStreamContent | null) => void;
  setTcpStreamLoading: (loading: boolean) => void;
  setConversationPackets: (packets: PacketSummary[]) => void;
  setConversationPacketsStatus: (status: string) => void;
  setSelectedCandidateGroupId: (id: string) => void;
  reset: () => void;
};

const initial = {
  activeTab: "diagnosis" as AgentPanelTab,
  toolTraceOpen: false,
  insightsOpen: false,
  rightHighlight: "" as RightHighlight,
  rootCauses: [] as RootCauseEntry[],
  tcpStreams: [] as TcpStreamRow[],
  tcpStreamContent: null,
  tcpStreamLoading: false,
  conversationPackets: [] as PacketSummary[],
  conversationPacketsStatus: "",
  selectedCandidateGroupId: ""
};

export const useAgentStore = create<AgentState>((set) => ({
  ...initial,

  setActiveTab: (activeTab) => set({ activeTab }),
  setToolTraceOpen: (toolTraceOpen) => set({ toolTraceOpen }),
  setInsightsOpen: (insightsOpen) => set({ insightsOpen }),
  setRightHighlight: (rightHighlight) => set({ rightHighlight }),
  setRootCauses: (rootCauses) => set({ rootCauses }),
  setTcpStreams: (tcpStreams) => set({ tcpStreams }),
  setTcpStreamContent: (tcpStreamContent) => set({ tcpStreamContent }),
  setTcpStreamLoading: (tcpStreamLoading) => set({ tcpStreamLoading }),
  setConversationPackets: (conversationPackets) => set({ conversationPackets }),
  setConversationPacketsStatus: (conversationPacketsStatus) => set({ conversationPacketsStatus }),
  setSelectedCandidateGroupId: (selectedCandidateGroupId) => set({ selectedCandidateGroupId }),
  reset: () => set(initial)
}));
