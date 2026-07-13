// Service 装配层：从 routes.ts 抽离，把 13 个 service + 2 个 answer builder + 协议适配器 wiring
// 集中在一个文件。routes.ts 只负责 HTTP handler → service 方法 的薄映射。
//
// 设计：composeServices 接收共享可变状态（cases 缓存、agentRuntimeStatus）和基础 helper
// （loadGraph、cacheCase），返回 route 层需要的所有 service 对象和 helper。
// formatBeijingTime / buildAgentQuestion 是 service 装配的依赖，也在这里定义。
import type { z } from "zod";
import type { CaseGraph } from "../../../../packages/shared/src/index.js";
import { runPcapTroubleshootingAgent } from "../agents/runtime.js";
import { createCaseGraphTools } from "../agents/caseGraphTools.js";
import { findBypassPattern, incrementHitCount, learnFromAgentRun, loadLearnedPatterns } from "../services/patternLearner.js";
import { apiConfig } from "../config.js";
import {
  getConversationPacketsWithMcp,
  listDnsPacketsWithMcp,
  listHttpPacketsWithMcp,
  listIcmpEventsWithMcp,
  listTcpResetsWithMcp,
  listTcpRetransmissionsWithMcp,
  listTcpZeroWindowWithMcp,
  listTlsPacketsWithMcp,
  listUdpPacketsWithMcp,
  queryPacketsWithMcp
} from "../mcp/tsharkQueryClient.js";
import { groupPacketPairs, noCaptureAnswer, pairGroupFromPackets, pairKey, protocolPacketCard, createPacketPairAnswer, createProtocolQueryAnswer } from "../protocolAdapters/builders.js";
import { createDnsAdapter } from "../protocolAdapters/dns.js";
import { createHttpAdapter } from "../protocolAdapters/http.js";
import { createIcmpAdapter } from "../protocolAdapters/icmp.js";
import { createTcpAdapters } from "../protocolAdapters/tcp.js";
import { createTlsAdapter } from "../protocolAdapters/tls.js";
import { type ProtocolAdapter, type ProtocolAdapterContext } from "../protocolAdapters/types.js";
import { createUdpAdapter } from "../protocolAdapters/udp.js";
import { writeCaseGraph, capturesDirectory } from "./caseStore.js";
import { createAgentAnswerService } from "../services/agentAnswerService.js";
import { createEvidenceOpenService } from "../services/evidenceOpenService.js";
import { runLevel1Insights } from "../services/insightEngine.js";
import { createAgentToolRegistryService } from "../services/agentToolRegistryService.js";
import { createPlannerService } from "../services/plannerService.js";
import { createAgentRuntimeService, type AgentChatRequest } from "../services/agentRuntimeService.js";
import { createProtocolEventQueryService } from "../services/protocolEventQueryService.js";
import { createQueryRunApiService } from "../services/queryRunApiService.js";
import { createQueryRunService } from "../services/queryRunService.js";
import { createStatisticsQueryService } from "../services/statisticsQueryService.js";
import { createToolRunService } from "../services/toolRunService.js";

// route 层提供的共享依赖：内存缓存读写 + 运行时状态（可变引用）
export type ServiceDeps = {
  loadGraph: (caseId: string) => CaseGraph;
  cacheCase: (caseId: string, graph: CaseGraph) => void;
  agentRuntimeStatus: {
    lastRunAt: string;
    lastStatus: string;
    lastError: string;
    lastCaseId: string;
    lastModel: string;
    lastBaseURL: string;
  };
};

export function formatBeijingTime(epochSeconds: number) {
  return new Date(epochSeconds * 1000).toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

// buildAgentQuestion 的入参类型与 routes.ts 的 AgentRequestSchema 推断结构一致；
// 直接复用 agentRuntimeService 的 AgentChatRequest，避免对 routes 的循环依赖
export function buildAgentQuestion(input: AgentChatRequest) {
  const depthInstruction = [
    input.thinkingDepth ? `思考深度：${input.thinkingDepth}` : "",
    input.reasoningDepth ? `推理深度：${input.reasoningDepth}` : ""
  ].filter(Boolean).join("；");
  const history = input.chatHistory.slice(-12)
    .filter((message) => message.content.trim())
    .map((message) => `${message.role === "user" ? "用户" : "Agent"}：${message.content.trim().slice(0, 1200)}`)
    .join("\n\n");
  return [
    history ? `以下是当前案例下最近的聊天上下文，只用于理解指代和延续问题，不得覆盖 case graph 证据：\n${history}` : "",
    `用户当前问题：${input.question}`,
    depthInstruction ? `本次回答控制：${depthInstruction}` : ""
  ].filter(Boolean).join("\n\n");
}

// 从 QueryRuns 自动提取 findings 到 memory
export function syncMemoryFromQueryRuns(graph: CaseGraph): CaseGraph {
  const existingIds = new Set((graph.memory?.findings || []).map((f) => f.queryRunId).filter(Boolean));
  const newFindings = graph.queryRuns
    .filter((qr) => !existingIds.has(qr.queryRunId))
    .map((qr) => {
      const problems = qr.selectedDiagnosis?.checks?.filter((c) => c.status === "problem").map((c) => c.summary || c.label) || [];
      const conclusion = problems.length ? problems.join("；") : qr.selectedDiagnosis?.summary || "完成分析";
      return { query: qr.question, conclusion, queryRunId: qr.queryRunId };
    });
  if (!newFindings.length) return graph;
  const memory = { ...graph.memory, findings: [...(graph.memory?.findings || []), ...newFindings].slice(-20) };
  const nextGraph = { ...graph, memory };
  writeCaseGraph(nextGraph);
  // 注意：cacheCase 由 route 层持有 cases Map，这里通过返回 nextGraph 让调用方刷新缓存
  return nextGraph;
}

export function updateMemory(graph: CaseGraph, patch: Partial<{ topology: string; userNotes: string[] }>): CaseGraph {
  const memory = {
    ...graph.memory,
    ...patch,
    userNotes: patch.userNotes ? [...(graph.memory?.userNotes || []), ...patch.userNotes] : graph.memory?.userNotes
  };
  const nextGraph = { ...graph, memory };
  writeCaseGraph(nextGraph);
  return nextGraph;
}

export type ComposedServices = ReturnType<typeof composeServices>;

export function composeServices(deps: ServiceDeps) {
  const { loadGraph, cacheCase, agentRuntimeStatus } = deps;
  const setGraph = (caseId: string, graph: CaseGraph) => cacheCase(caseId, graph);
  const setCaseGraph = setGraph;

  // case graph 进程内工具：读内存 graph，写操作直接持久化到 caseStore
  function createCaseGraphToolsFor(caseId: string) {
    return createCaseGraphTools({
      loadGraph: () => loadGraph(caseId),
      saveGraph: (graph) => {
        writeCaseGraph(graph);
        cacheCase(graph.spec.caseId, graph);
      }
    });
  }

  const toolRunService = createToolRunService({
    readGraph: loadGraph,
    writeGraph: writeCaseGraph,
    setGraph
  });
  const { recordToolRun, recordPlannerRun, recordAnswerRun, recordErrorRun, recordMcpRun, recordQueryRunMcp } = toolRunService;
  const evidenceOpenService = createEvidenceOpenService({
    capturesDirectory,
    writeGraph: writeCaseGraph,
    setGraph,
    recordMcpRun
  });
  const agentAnswerService = createAgentAnswerService({
    evidencePacketSampleLimit: apiConfig.diagnosis.evidencePacketSampleLimit
  });
  const {
    queryRunAnswer,
    selectedSessionProblemAnswer,
    usageHelpAnswer,
    activeQueryRunAnswer,
    troubleshootingScopeAnswer,
    diagnosticInterviewAnswer,
    reportAnswer,
    answerWithPlannerThought
  } = agentAnswerService;
  const queryRunService = createQueryRunService({
    candidateGroupLimit: apiConfig.query.candidateGroupLimit,
    queryPacketLimit: apiConfig.query.queryPacketLimit,
    conversationPacketLimit: apiConfig.query.conversationPacketLimit,
    retainedQueryRunLimit: apiConfig.query.retainedQueryRunLimit,
    shortConversationPacketThreshold: apiConfig.diagnosis.shortConversationPacketThreshold,
    retransmissionBurstThreshold: apiConfig.diagnosis.retransmissionBurstThreshold,
    duplicateAckBurstThreshold: apiConfig.diagnosis.duplicateAckBurstThreshold,
    evidencePacketSampleLimit: apiConfig.diagnosis.evidencePacketSampleLimit,
    transportEvidencePacketSampleLimit: apiConfig.diagnosis.transportEvidencePacketSampleLimit,
    finEvidencePacketSampleLimit: apiConfig.diagnosis.finEvidencePacketSampleLimit,
    timeOverlapToleranceSeconds: apiConfig.pathCorrelation.timeOverlapToleranceSeconds,
    fallbackPatterns: apiConfig.planner.fallbackPatterns,
    capturesDirectory,
    writeCaseGraph,
    setGraph,
    recordQueryRunMcp,
    recordMcpRun,
    formatBeijingTime
  });
  const {
    captureQueryInputs,
    buildAccessCandidateGroups,
    buildQueryPath,
    buildQueryDiagnosis,
    inferQueryRunInput,
    requestedLimit,
    displayFilterFromQuestion,
    createQueryRun,
    selectConversation,
    createCaptureCorrelationQueryRun,
    applyCorrelationContextAndRerun,
    activeCorrelationNeedsContext,
    shouldApplyCorrelationContext,
    shouldCorrelateCaptures,
    shouldCreateQueryRun
  } = queryRunService;
  const queryRunApiService = createQueryRunApiService({
    loadGraph,
    writeCaseGraph,
    setGraph,
    capturesDirectory,
    conversationPacketLimit: apiConfig.query.conversationPacketLimit,
    inferQueryRunInput,
    createQueryRun,
    selectConversation,
    getConversationPackets: getConversationPacketsWithMcp,
    evidenceOpenService
  });
  const statisticsQueryService = createStatisticsQueryService({
    retainedQueryRunLimit: apiConfig.query.retainedQueryRunLimit,
    captureQueryInputs,
    writeCaseGraph,
    setGraph,
    recordMcpRun,
    recordQueryRunMcp,
    formatBeijingTime
  });
  const { deterministicStatisticsAnswer, isProtocolStatisticsQuestion } = statisticsQueryService;

  const packetPairAnswer = createPacketPairAnswer({
    conversationPacketLimit: apiConfig.query.conversationPacketLimit,
    retainedQueryRunLimit: apiConfig.query.retainedQueryRunLimit,
    captureQueryInputs,
    getConversationPackets: getConversationPacketsWithMcp,
    buildAccessCandidateGroups,
    buildQueryPath,
    buildQueryDiagnosis,
    writeCaseGraph,
    setCaseGraph,
    formatBeijingTime
  });
  const protocolQueryAnswer = createProtocolQueryAnswer({
    retainedQueryRunLimit: apiConfig.query.retainedQueryRunLimit,
    writeCaseGraph,
    setCaseGraph
  });

  const protocolAdapterContext: ProtocolAdapterContext = {
    queryPacketLimit: apiConfig.query.queryPacketLimit,
    captureQueryInputs,
    requestedLimit,
    displayFilterFromQuestion,
    noCaptureAnswer,
    packetPairAnswer,
    protocolPacketCard,
    protocolQueryAnswer,
    groupPacketPairs,
    pairKey,
    pairGroupFromPackets,
    formatBeijingTime,
    queryPackets: queryPacketsWithMcp,
    listTcpResets: listTcpResetsWithMcp,
    listTcpRetransmissions: listTcpRetransmissionsWithMcp,
    listTcpZeroWindow: listTcpZeroWindowWithMcp,
    listIcmpEvents: listIcmpEventsWithMcp,
    listDnsPackets: listDnsPacketsWithMcp,
    listUdpPackets: listUdpPacketsWithMcp,
    listTlsPackets: listTlsPacketsWithMcp,
    listHttpPackets: listHttpPacketsWithMcp
  };

  const protocolAdapters: ProtocolAdapter[] = [
    ...createTcpAdapters(protocolAdapterContext),
    createDnsAdapter(protocolAdapterContext),
    createIcmpAdapter(protocolAdapterContext),
    createUdpAdapter(protocolAdapterContext),
    createTlsAdapter(protocolAdapterContext),
    createHttpAdapter(protocolAdapterContext)
  ];
  const protocolEventQueryService = createProtocolEventQueryService({
    adapters: protocolAdapters,
    hasLlmApiKey: () => Boolean(apiConfig.llm.apiKey),
    loadLearnedPatterns,
    learnFromAgentRun: (question, toolCalls, adapterIds) => {
      learnFromAgentRun(question, toolCalls, adapterIds).catch(() => {});
    },
    incrementHitCount,
    createCaseGraphTools: (caseId) => createCaseGraphToolsFor(caseId)
  });
  const agentToolRegistryService = createAgentToolRegistryService({
    usageHelpAnswer,
    deterministicStatisticsAnswer,
    activeCorrelationNeedsContext,
    applyCorrelationContextAndRerun,
    createCaptureCorrelationQueryRun,
    runProtocolEventQuery: protocolEventQueryService.run,
    inferQueryRunInput,
    createQueryRun,
    queryRunAnswer,
    selectedSessionProblemAnswer,
    activeQueryRunAnswer,
    reportAnswer,
    troubleshootingScopeAnswer,
    loadGraph,
    recordToolRun,
    runLlmExplain: async (graph, question) => {
      // leader 提示词依赖 get_case_memory/load_case_graph 等 case graph 工具，必须随调用注入
      const answer = await runPcapTroubleshootingAgent({ graph, question, chatHistory: undefined, tools: createCaseGraphToolsFor(graph.spec.caseId) });
      return answer;
    }
  });
  const plannerService = createPlannerService({
    hasLlmApiKey: () => Boolean(apiConfig.llm.apiKey),
    executeToolIntent: agentToolRegistryService.execute
  });
  const {
    planChain,
    executeAgentIntentPlan,
    executeChainStep
  } = plannerService;

  const agentRuntimeService = createAgentRuntimeService({
    planChain,
    executeAgentIntentPlan,
    executeChainStep,
    loadGraph,
    buildAgentQuestion,
    answerWithPlannerThought,
    diagnosticInterviewAnswer,
    // syncMemoryFromQueryRuns 写回后需同步刷新缓存，这里包装一层把 cacheCase 补上
    syncMemoryFromQueryRuns: (graph) => {
      const next = syncMemoryFromQueryRuns(graph);
      if (next !== graph) cacheCase(graph.spec.caseId, next);
      return next;
    },
    recordPlannerRun,
    recordAnswerRun,
    recordErrorRun,
    updateRuntimeStatus: (patch) => Object.assign(agentRuntimeStatus, patch),
    adapterIds: protocolEventQueryService.adapterIds,
    createAgentTools: (caseId, question) => [...createCaseGraphToolsFor(caseId), ...agentToolRegistryService.createSdkTools(caseId, question)],
    learnFromAgentRun: (question, toolCalls, adapterIds) => {
      learnFromAgentRun(question, toolCalls, adapterIds).catch(() => {});
    },
    findLearnedBypass: (question) => findBypassPattern(question, apiConfig.planner.learnedBypassMinHits)
  });

  return {
    agentRuntimeService,
    queryRunApiService,
    evidenceOpenService,
    agentToolRegistryService,
    statisticsQueryService,
    protocolEventQueryService,
    queryRunService,
    toolRunService,
    // route 层 helpers 需要的零散方法
    captureQueryInputs,
    buildQueryPath,
    inferQueryRunInput,
    isProtocolStatisticsQuestion,
    deterministicStatisticsAnswer,
    reportAnswer,
    answerWithPlannerThought,
    formatBeijingTime,
    buildAgentQuestion,
    syncMemoryFromQueryRuns,
    updateMemory,
    createCaseGraphToolsFor,
    recordToolRun,
    recordMcpRun,
    recordQueryRunMcp,
    runLevel1Insights
  };
}
