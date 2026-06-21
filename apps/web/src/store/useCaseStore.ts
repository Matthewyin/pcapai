/*
 * useCaseStore — 案例领域状态：当前案例图 / 历史列表 / 映射提示 / 抓包草稿 / 分析过滤。
 *
 * 阶段 0：骨架。当前 main.tsx 仍用本地 useState 管理这些字段，本 store 是后续迁移目标。
 * 不持久化（数据从 API 来；需要跨会话保留的 id 由 main.tsx 的 localStorage key 管理，
 * 阶段 1 拆 Sidebar 时再迁过来）。
 *
 * 迁移映射（main.tsx → store）：
 *   graph / setGraph                          → graph / setGraph
 *   caseHistory / setCaseHistory              → caseHistory / setCaseHistory
 *   mappingHints / setMappingHints            → mappingHints / setMappingHints
 *   timeOffsetHints / setTimeOffsetHints      → timeOffsetHints / setTimeOffsetHints
 *   captureDrafts / setCaptureDrafts          → captureDrafts / setCaptureDrafts
 *   analysisFilter / setAnalysisFilter        → analysisFilter / setAnalysisFilter
 *   pinnedCaseIds / setPinnedCaseIds          → pinnedCaseIds / togglePinnedCase
 *   selectedCaseIds / setSelectedCaseIds      → selectedCaseIds（历史页批量选择）
 *   caseForm / createFlowOpen / createStep    → 新建案例向导
 *   lastActiveCaseId / lastActiveRunId        → 持久化的最后活动 id（localStorage）
 */
import { create } from "zustand";
import type {
  CaseGraph,
  CaseSummary,
  MappingHint,
  TimeOffsetHint,
  CaptureDraft
} from "../types";

type CaseState = {
  /** 当前打开的案例图（CaseGraph 是后端权威） */
  graph: CaseGraph | null;
  /** 历史案例列表（侧栏 + 历史页共用） */
  caseHistory: CaseSummary[];
  /** 置顶案例 id（PINNED_CASES_KEY，跨会话持久） */
  pinnedCaseIds: string[];
  /** 历史页批量选择（删除/对比用） */
  selectedCaseIds: string[];

  /** 映射提示（NAT/SLB/代理，影响 TCP 预处理聚焦流） */
  mappingHints: MappingHint[];
  /** 时间偏移提示（多抓包点对齐） */
  timeOffsetHints: TimeOffsetHint[];
  /** 待上传抓包草稿（文件 + nodeId + 角色） */
  captureDrafts: CaptureDraft[];
  /** 分析过滤（client/server/protocol/port） */
  analysisFilter: { client: string; server: string; protocol: string; port: string };

  /** 新建案例向导 */
  caseForm: { title: string };
  createFlowOpen: boolean;
  createStep: number;

  /** 持久化的活动 id（localStorage，下次启动自动恢复） */
  lastActiveCaseId: string;
  lastActiveRunId: string;

  setGraph: (graph: CaseGraph | null) => void;
  setCaseHistory: (history: CaseSummary[]) => void;
  setMappingHints: (hints: MappingHint[]) => void;
  setTimeOffsetHints: (hints: TimeOffsetHint[]) => void;
  setCaptureDrafts: (drafts: CaptureDraft[]) => void;
  setAnalysisFilter: (filter: Partial<CaseState["analysisFilter"]>) => void;
  togglePinnedCase: (caseId: string) => void;
  setSelectedCaseIds: (ids: string[]) => void;
  setCaseForm: (form: Partial<CaseState["caseForm"]>) => void;
  setCreateFlowOpen: (open: boolean) => void;
  setCreateStep: (step: number) => void;
  setLastActive: (caseId?: string, runId?: string) => void;
};

export const useCaseStore = create<CaseState>((set, get) => ({
  graph: null,
  caseHistory: [],
  pinnedCaseIds: [],
  selectedCaseIds: [],
  mappingHints: [],
  timeOffsetHints: [],
  captureDrafts: [],
  analysisFilter: { client: "", server: "", protocol: "", port: "" },
  caseForm: { title: "新建离线排障案例" },
  createFlowOpen: false,
  createStep: 1,
  lastActiveCaseId: "",
  lastActiveRunId: "",

  setGraph: (graph) => set({ graph }),
  setCaseHistory: (caseHistory) => set({ caseHistory }),
  setMappingHints: (mappingHints) => set({ mappingHints }),
  setTimeOffsetHints: (timeOffsetHints) => set({ timeOffsetHints }),
  setCaptureDrafts: (captureDrafts) => set({ captureDrafts }),
  setAnalysisFilter: (filter) => set({ analysisFilter: { ...get().analysisFilter, ...filter } }),
  togglePinnedCase: (caseId) => {
    const current = get().pinnedCaseIds;
    set({
      pinnedCaseIds: current.includes(caseId)
        ? current.filter((id) => id !== caseId)
        : [...current, caseId]
    });
  },
  setSelectedCaseIds: (selectedCaseIds) => set({ selectedCaseIds }),
  setCaseForm: (form) => set({ caseForm: { ...get().caseForm, ...form } }),
  setCreateFlowOpen: (createFlowOpen) => set({ createFlowOpen }),
  setCreateStep: (createStep) => set({ createStep }),
  setLastActive: (caseId, runId) =>
    set({
      ...(caseId !== undefined ? { lastActiveCaseId: caseId } : {}),
      ...(runId !== undefined ? { lastActiveRunId: runId } : {})
    })
}));
