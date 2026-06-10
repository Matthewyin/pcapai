import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import {
  CaptureNodeSchema,
  CaseSpecSchema,
  MappingHintSchema,
  TimeOffsetHintSchema,
  type CaseGraph,
  type EvidenceCard,
  type QueryRun,
} from "../../../../packages/shared/src/index.js";
import { runAgentCompatibilityCheck, runPcapTroubleshootingAgent } from "../agents/runtime.js";
import { deleteLearnedPattern, incrementHitCount, learnFromAgentRun, listLearnedPatterns, loadLearnedPatterns } from "../services/patternLearner.js";
import { apiConfig } from "../config.js";
import { getCaptureTimeRangeWithMcp, getConversationPacketsWithMcp, listDnsPacketsWithMcp, listHttpPacketsWithMcp, listIcmpEventsWithMcp, listTcpResetsWithMcp, listTcpRetransmissionsWithMcp, listTcpStreamsWithMcp, followTcpStreamWithMcp, listTcpZeroWindowWithMcp, listTlsPacketsWithMcp, listUdpPacketsWithMcp, queryPacketsWithMcp } from "../mcp/tsharkQueryClient.js";
import { createPacketPairAnswer, createProtocolQueryAnswer, groupPacketPairs, noCaptureAnswer, pairGroupFromPackets, pairKey, protocolPacketCard } from "../protocolAdapters/builders.js";
import { createDnsAdapter } from "../protocolAdapters/dns.js";
import { createHttpAdapter } from "../protocolAdapters/http.js";
import { createIcmpAdapter } from "../protocolAdapters/icmp.js";
import { createTcpAdapters } from "../protocolAdapters/tcp.js";
import { createTlsAdapter } from "../protocolAdapters/tls.js";
import { type ProtocolAdapter, type ProtocolAdapterContext } from "../protocolAdapters/types.js";
import { createUdpAdapter } from "../protocolAdapters/udp.js";
import { stripPayload } from "./capturePreprocess.js";
import { addCapture, capturesDirectory, caseDirectory, createEmptyCase, deleteCases, listCaseSummaries, readAnalysisRunSnapshot, readCaseGraph, safePathPart, writeCaseGraph } from "./caseStore.js";
import { activateLlmProfile, deleteLlmProfiles, getLlmSettings, listLlmProfiles, parseProviderData, saveLlmProfile, saveLlmSettings } from "./llmSettings.js";
import { buildCaseReportMarkdown } from "./reportBuilder.js";
import { createAgentAnswerService } from "../services/agentAnswerService.js";
import { createEvidenceOpenService } from "../services/evidenceOpenService.js";
import { runLevel1Insights } from "../services/insightEngine.js";
import { extractTcpAnomalies } from "../services/tcpPreprocessor.js";
import { createAgentToolRegistryService } from "../services/agentToolRegistryService.js";
import { createPlannerService } from "../services/plannerService.js";
import { createAgentRuntimeService } from "../services/agentRuntimeService.js";
import { createProtocolEventQueryService } from "../services/protocolEventQueryService.js";
import { createQueryRunApiService } from "../services/queryRunApiService.js";
import { createQueryRunService } from "../services/queryRunService.js";
import { createStatisticsQueryService } from "../services/statisticsQueryService.js";
import { createToolRunService } from "../services/toolRunService.js";

const cases = new Map<string, CaseGraph>();
const agentRuntimeStatus = {
  lastRunAt: "",
  lastStatus: "not_run",
  lastError: "",
  lastCaseId: "",
  lastModel: "",
  lastBaseURL: ""
};
const CreateCaseRequestSchema = z.object({
  caseId: z.string().min(1).optional(),
  title: z.string().min(1)
});
const UpdateCaseRequestSchema = z.object({
  title: z.string().min(1)
});
const LlmSettingsRequestSchema = z.object({
  baseURL: z.string().url(),
  model: z.string().min(1),
  apiKey: z.string().optional(),
  providerData: z.string().optional()
});
const LlmTestRequestSchema = LlmSettingsRequestSchema;
const LlmProfileRequestSchema = LlmSettingsRequestSchema.extend({
  profileId: z.string().min(1).optional(),
  name: z.string().min(1)
});
const DeleteLlmProfilesRequestSchema = z.object({
  profileIds: z.array(z.string().min(1)).min(1)
});
const DeleteCasesRequestSchema = z.object({
  caseIds: z.array(z.string().min(1)).min(1)
});
const AgentRequestSchema = z.object({
  question: z.string().default(""),
  chatHistory: z.array(z.object({
    role: z.enum(["user", "assistant"]),
    content: z.string()
  })).default([]),
  profileId: z.string().min(1).optional(),
  thinkingDepth: z.string().min(1).optional(),
  reasoningDepth: z.string().min(1).optional()
});
const CaptureMetadataSchema = z.object({
  originalName: z.string(),
  nodeId: z.string().min(1),
  name: z.string().min(1),
  role: z.string().min(1),
  interfaceDirection: z.enum(["ingress", "egress", "bidirectional", "unknown"]),
  capturePosition: z.string().default("")
});
const CaptureMetadataListSchema = z.array(CaptureMetadataSchema);
const MappingHintListSchema = z.array(MappingHintSchema);
const TimeOffsetHintListSchema = z.array(TimeOffsetHintSchema);
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, callback) => {
      const directory = capturesDirectory(String(req.params.caseId));
      mkdirSync(directory, { recursive: true });
      callback(null, directory);
    },
    filename: (_req, file, callback) => {
      callback(null, `${Date.now()}-${safePathPart(file.originalname)}`);
    }
  })
});

function loadGraph(caseId: string) {
  const cached = cases.get(caseId);
  if (cached) return cached;
  const graph = readCaseGraph(caseId);
  cases.set(caseId, graph);
  return graph;
}

const toolRunService = createToolRunService({
  readGraph: loadGraph,
  writeGraph: writeCaseGraph,
  setGraph: (caseId, graph) => cases.set(caseId, graph)
});
const { recordToolRun, recordPlannerRun, recordAnswerRun, recordErrorRun, recordMcpRun, recordQueryRunMcp } = toolRunService;
const evidenceOpenService = createEvidenceOpenService({
  capturesDirectory,
  writeGraph: writeCaseGraph,
  setGraph: (caseId, graph) => cases.set(caseId, graph),
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
  setGraph: (caseId, graph) => cases.set(caseId, graph),
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
  setGraph: (caseId, graph) => cases.set(caseId, graph),
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
  setGraph: (caseId, graph) => cases.set(caseId, graph),
  recordMcpRun,
  recordQueryRunMcp,
  formatBeijingTime
});
const { deterministicStatisticsAnswer, isProtocolStatisticsQuestion } = statisticsQueryService;

function parseCaptureMetadata(raw: unknown) {
  if (typeof raw !== "string") return null;
  try {
    return CaptureMetadataListSchema.safeParse(JSON.parse(raw));
  } catch {
    return null;
  }
}

function fallbackCaptureMetadata(body: Record<string, unknown>, files: Express.Multer.File[]) {
  const firstValue = (value: unknown) => Array.isArray(value) ? value[0] : value;
  return CaptureMetadataListSchema.safeParse(files.map((file, index) => ({
    originalName: file.originalname,
    nodeId: String(firstValue(body.nodeId) || `node-${index + 1}`),
    name: String(firstValue(body.name) || file.originalname.replace(/\.[^.]+$/, "") || `抓包节点 ${index + 1}`),
    role: String(firstValue(body.role) || "未知节点"),
    interfaceDirection: firstValue(body.interfaceDirection) || "unknown",
    capturePosition: String(firstValue(body.capturePosition) || "")
  })));
}

type CaptureTimeRange = Awaited<ReturnType<typeof getCaptureTimeRangeWithMcp>>;

async function readCaptureTimeRanges(graph: CaseGraph, captures = graph.captures) {
  const captureInputs = captures
    .filter((capture) => capture.pcapFilename)
    .map((capture) => ({
      nodeId: capture.nodeId,
      name: capture.name,
      pcapFilename: capture.pcapFilename,
      pcapPath: path.join(capturesDirectory(graph.spec.caseId), capture.pcapFilename!)
    }));
  return Promise.all(captureInputs.map((capture) => getCaptureTimeRangeWithMcp({ capture })));
}

function captureEvidenceCardsFromRanges(ranges: CaptureTimeRange[]): EvidenceCard[] {
  return ranges.map((range) => {
    const timeText = range.firstPacketTime && range.lastPacketTime
      ? `${formatBeijingTime(range.firstPacketTime)} 到 ${formatBeijingTime(range.lastPacketTime)}`
      : "未读取到时间戳";
    return {
      cardId: `capture-${range.nodeId}-${Date.now()}`,
      kind: "capture" as const,
      title: range.pcapFilename,
      summary: `已收到 ${range.packetCount} 个包，时间范围 ${timeText}。`,
      pcapFilename: range.pcapFilename,
      actions: ["request_upload" as const]
    };
  });
}

async function captureEvidenceCards(graph: CaseGraph, captures = graph.captures): Promise<EvidenceCard[]> {
  return captureEvidenceCardsFromRanges(await readCaptureTimeRanges(graph, captures));
}

function graphWithCaptureTimeRanges(graph: CaseGraph, ranges: CaptureTimeRange[]): CaseGraph {
  return {
    ...graph,
    captures: graph.captures.map((capture) => {
      const range = ranges.find((item) => item.nodeId === capture.nodeId && item.pcapFilename === capture.pcapFilename);
      return range
        ? { ...capture, packetCount: range.packetCount, firstPacketTime: range.firstPacketTime, lastPacketTime: range.lastPacketTime }
        : capture;
    })
  };
}

function resetAnalysis(graph: CaseGraph) {
  return {
    ...graph,
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    queryRuns: [],
    activeQueryRunId: undefined,
    path: {
      nodes: graph.path.nodes.map((node) => ({ ...node, status: "unknown" as const })),
      edges: []
    }
  };
}

async function loadGraphWithInsights(caseId: string): Promise<CaseGraph> {
  const graph = loadGraph(caseId);
  if (graph.insights?.length) return graph;

  // 如果 graph 没有 packets 但有 captures，先跑 TCP 预处理抽取异常包
  if (!graph.packets.length && graph.captures.length) {
    try {
      const inputs = captureQueryInputs(graph);
      if (inputs.length) {
        const packets = await extractTcpAnomalies(inputs, graph.mappingHints);
        if (packets.length) {
          const enriched = { ...graph, packets };
          writeCaseGraph(enriched);
          cases.set(caseId, enriched);
          const insights = runLevel1Insights(enriched);
          if (insights.length) {
            const nextGraph = { ...enriched, insights };
            writeCaseGraph(nextGraph);
            cases.set(caseId, nextGraph);
            return nextGraph;
          }
          return enriched;
        }
      }
    } catch { /* tshark 查询失败不阻塞后续流程 */ }
  }

  if (graph.packets.length) {
    const insights = runLevel1Insights(graph);
    if (insights.length) {
      const nextGraph = { ...graph, insights };
      writeCaseGraph(nextGraph);
      cases.set(caseId, nextGraph);
      return nextGraph;
    }
  }
  return graph;
}

const setCaseGraph = (caseId: string, graph: CaseGraph) => cases.set(caseId, graph);

// 从 QueryRuns 自动提取 findings 到 memory
function syncMemoryFromQueryRuns(graph: CaseGraph): CaseGraph {
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
  cases.set(graph.spec.caseId, nextGraph);
  return nextGraph;
}

function updateMemory(graph: CaseGraph, patch: Partial<{ topology: string; userNotes: string[] }>): CaseGraph {
  const memory = {
    ...graph.memory,
    ...patch,
    userNotes: patch.userNotes ? [...(graph.memory?.userNotes || []), ...patch.userNotes] : graph.memory?.userNotes
  };
  const nextGraph = { ...graph, memory };
  writeCaseGraph(nextGraph);
  cases.set(graph.spec.caseId, nextGraph);
  return nextGraph;
}
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
  incrementHitCount
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
    const answer = await runPcapTroubleshootingAgent({ graph, question, chatHistory: undefined });
    return answer;
  }
});
const plannerService = createPlannerService({
  fallbackPatterns: apiConfig.planner.fallbackPatterns,
  hasLlmApiKey: () => Boolean(apiConfig.llm.apiKey),
  isProtocolStatisticsQuestion,
  shouldApplyCorrelationContext,
  shouldCorrelateCaptures,
  shouldCreateQueryRun,
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
  syncMemoryFromQueryRuns,
  recordPlannerRun,
  recordAnswerRun,
  recordErrorRun,
  updateRuntimeStatus: (patch) => Object.assign(agentRuntimeStatus, patch),
  adapterIds: protocolEventQueryService.adapterIds,
  createAgentTools: (caseId, question) => agentToolRegistryService.createSdkTools(caseId, question),
  learnFromAgentRun: (question, toolCalls, adapterIds) => {
    learnFromAgentRun(question, toolCalls, adapterIds).catch(() => {});
  }
});

export const pathCorrelationTestHooks = {
  buildQueryPath
};

function formatBeijingTime(epochSeconds: number) {
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


function buildAgentQuestion(input: z.infer<typeof AgentRequestSchema>) {
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

function writeStreamEvent(res: { write: (chunk: string) => void }, event: string, data: unknown) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function testOpenAICompatibleConfig(input: z.infer<typeof LlmTestRequestSchema>) {
  const apiKey = input.apiKey || apiConfig.llm.apiKey;
  if (!apiKey) return { ok: false, error: "API Key 不能为空，或先保存已有 Key。" };
  const endpoint = `${input.baseURL.replace(/\/+$/, "")}/chat/completions`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model: input.model,
      messages: [{ role: "user", content: "ping" }],
      max_tokens: 8,
      stream: false,
      ...parseProviderData(input.providerData)
    })
  });
  if (!response.ok) {
    const body = await response.text();
    return { ok: false, status: response.status, error: body.slice(0, 500) || response.statusText };
  }
  return { ok: true, status: response.status };
}

async function testAgentCompatibleConfig(input: z.infer<typeof LlmTestRequestSchema>) {
  const apiKey = input.apiKey || apiConfig.llm.apiKey;
  if (!apiKey) return { ok: false, error: "API Key 不能为空，或先保存已有 Key。" };
  const providerData = parseProviderData(input.providerData);
  return runAgentCompatibilityCheck({
    apiKey,
    baseURL: input.baseURL,
    model: input.model,
    providerData
  });
}

export function createAgentRouter() {
  const router = Router();

  router.get("/health", (_req, res) => {
    res.json({ status: "ok", runtime: "node", agents: "openai-agents-js" });
  });

  router.get("/settings/llm", (_req, res) => {
    res.json(getLlmSettings());
  });

  router.get("/settings/llm/runtime", (_req, res) => {
    res.json({
      settings: getLlmSettings(),
      useResponses: apiConfig.llm.useResponses,
      agent: agentRuntimeStatus
    });
  });

  router.post("/settings/llm", (req, res) => {
    const parsed = LlmSettingsRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      return res.json({ ...saveLlmSettings(parsed.data), profiles: listLlmProfiles() });
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/settings/llm/profiles", (_req, res) => {
    res.json({ profiles: listLlmProfiles(), settings: getLlmSettings() });
  });

  router.post("/settings/llm/profiles", (req, res) => {
    const parsed = LlmProfileRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      return res.json({ ...saveLlmProfile(parsed.data), profiles: listLlmProfiles() });
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/settings/llm/profiles/:profileId/activate", (req, res) => {
    const settings = activateLlmProfile(String(req.params.profileId));
    if (!settings) return res.status(404).json({ error: "llm profile not found" });
    return res.json({ settings, profiles: listLlmProfiles() });
  });

  router.delete("/settings/llm/profiles", (req, res) => {
    const parsed = DeleteLlmProfilesRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    return res.json(deleteLlmProfiles(parsed.data.profileIds));
  });

  router.get("/settings/learned-patterns", (_req, res) => {
    res.json({ patterns: listLearnedPatterns() });
  });

  router.delete("/settings/learned-patterns", (req, res) => {
    const { regex, adapterId } = req.body || {};
    if (typeof regex !== "string" || typeof adapterId !== "string") return res.status(400).json({ error: "regex 和 adapterId 是必填字符串" });
    const deleted = deleteLearnedPattern(regex, adapterId);
    return deleted ? res.json({ deleted: true }) : res.status(404).json({ error: "未找到匹配的 learned pattern" });
  });

  router.post("/settings/llm/test", async (req, res) => {
    const parsed = LlmTestRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      return res.json(await testOpenAICompatibleConfig(parsed.data));
    } catch (error) {
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/settings/llm/agent-test", async (req, res) => {
    const parsed = LlmTestRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      return res.json(await testAgentCompatibleConfig(parsed.data));
    } catch (error) {
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases", (req, res) => {
    const parsed = CreateCaseRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

    const caseId = parsed.data.caseId || safePathPart(`${parsed.data.title}-${Date.now()}`);
    const graph = createEmptyCase(CaseSpecSchema.parse({ ...parsed.data, caseId }));
    cases.set(caseId, graph);
    return res.status(201).json(graph);
  });

  router.get("/cases", (_req, res) => {
    return res.json({ cases: listCaseSummaries() });
  });

  router.delete("/cases", (req, res) => {
    const parsed = DeleteCasesRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    const deleted = deleteCases(parsed.data.caseIds);
    for (const caseId of parsed.data.caseIds) cases.delete(caseId);
    return res.json({ deleted, cases: listCaseSummaries() });
  });

  router.put("/cases/:caseId", (req, res) => {
    const parsed = UpdateCaseRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      const graph = loadGraph(req.params.caseId);
      const nextGraph: CaseGraph = { ...graph, spec: { ...graph.spec, title: parsed.data.title } };
      writeCaseGraph(nextGraph);
      cases.set(nextGraph.spec.caseId, nextGraph);
      return res.json(nextGraph);
    } catch {
      return res.status(404).json({ error: "case not found" });
    }
  });

  router.post("/cases/new-chat", (_req, res) => {
    const caseId = safePathPart(`new-chat-${Date.now()}`);
    const graph = createEmptyCase(CaseSpecSchema.parse({
      caseId,
      title: "新建数据包分析会话",
      protocol: "tcp"
    }));
    cases.set(caseId, graph);
    return res.status(201).json(graph);
  });

  router.post(`/cases/:caseId/captures`, upload.array(apiConfig.uploadFieldName), async (req, res) => {
    const caseId = String(req.params.caseId);
    const files = Array.isArray(req.files) ? req.files : [];
    if (!files.length) return res.status(400).json({ error: `${apiConfig.uploadFieldName} file is required` });
    const metadata = parseCaptureMetadata(req.body.metadata) || fallbackCaptureMetadata(req.body, files);
    if (!metadata?.success) return res.status(400).json({ error: "capture metadata is required" });

    try {
      let graph = loadGraph(caseId);
      const addedCaptures = [];
      for (const [index, file] of files.entries()) {
        const fileMetadata = metadata.data[index];
        if (!fileMetadata) return res.status(400).json({ error: `missing metadata for ${file.originalname}` });
        const strippedPath = await stripPayload(file.path);
        const pcapFilename = path.basename(strippedPath);
        const nodeInput = CaptureNodeSchema.safeParse({
          nodeId: fileMetadata.nodeId,
          name: fileMetadata.name,
          role: fileMetadata.role,
          interfaceDirection: fileMetadata.interfaceDirection,
          capturePosition: fileMetadata.capturePosition,
          pcapFilename
        });
        if (!nodeInput.success) return res.status(400).json({ error: nodeInput.error.flatten() });
        graph = addCapture(graph, nodeInput.data);
        addedCaptures.push(nodeInput.data);
      }
      const ranges = await readCaptureTimeRanges(graph, addedCaptures);
      graph = graphWithCaptureTimeRanges(resetAnalysis(graph), ranges);
      writeCaseGraph(graph);
      cases.set(caseId, graph);
      return res.status(201).json(graph);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post(`/cases/:caseId/attachments`, upload.array(apiConfig.uploadFieldName), async (req, res) => {
    const caseId = String(req.params.caseId);
    const files = Array.isArray(req.files) ? req.files : [];
    if (!files.length) return res.status(400).json({ error: `${apiConfig.uploadFieldName} file is required` });
    try {
      let graph = loadGraph(caseId);
      const addedCaptures = [];
      const baseNodeIndex = graph.captures.length;
      for (const [index, file] of files.entries()) {
        const strippedPath = await stripPayload(file.path);
        const pcapFilename = path.basename(strippedPath);
        const capture = CaptureNodeSchema.parse({
          nodeId: `node-${baseNodeIndex + index + 1}`,
          name: file.originalname.replace(/\.[^.]+$/, "") || `抓包节点 ${baseNodeIndex + index + 1}`,
          role: "unknown",
          interfaceDirection: "unknown",
          capturePosition: "",
          pcapFilename
        });
        graph = addCapture(graph, capture);
        addedCaptures.push(capture);
      }
      const ranges = await readCaptureTimeRanges(graph, addedCaptures);
      graph = graphWithCaptureTimeRanges(resetAnalysis(graph), ranges);
      const evidenceCards = captureEvidenceCardsFromRanges(ranges);
      writeCaseGraph(graph);
      cases.set(caseId, graph);
      return res.status(201).json({
        graph,
        evidenceCards,
        agentAnswer: {
          answer: [
            `已收到 ${files.length} 个数据包文件。`,
            ...evidenceCards.map((card) => `- ${card.summary}`),
            "请补充这些抓包节点的角色、抓包位置、入/出方向，以及故障时间、源地址、目的地址和端口。"
          ].join("\n"),
          thoughts: ["通过聊天附件接收 pcap。", "裁剪 payload 后用 tshark-query 读取时间范围。", "当前缺少节点上下文，先追问必要信息。"],
          evidenceCards,
          actions: ["request_upload"],
          missingContext: ["节点角色", "抓包位置", "入/出方向", "故障时间", "源地址", "目的地址", "端口"],
          confidence: "needs_context"
        }
      });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.put("/cases/:caseId/mapping-hints", (req, res) => {
    const parsed = MappingHintListSchema.safeParse(req.body?.mappingHints);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      const graph = loadGraph(String(req.params.caseId));
      const nextGraph: CaseGraph = { ...graph, mappingHints: parsed.data };
      writeCaseGraph(nextGraph);
      cases.set(graph.spec.caseId, nextGraph);
      return res.json(nextGraph);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.put("/cases/:caseId/time-offset-hints", (req, res) => {
    const parsed = TimeOffsetHintListSchema.safeParse(req.body?.timeOffsetHints);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      const graph = loadGraph(String(req.params.caseId));
      const nextGraph: CaseGraph = { ...graph, timeOffsetHints: parsed.data };
      writeCaseGraph(nextGraph);
      cases.set(graph.spec.caseId, nextGraph);
      return res.json(nextGraph);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs", async (req, res) => {
    try {
      const result = await queryRunApiService.create(String(req.params.caseId), req.body || {});
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.status(result.status || 200).json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId/query-runs/:queryRunId", (req, res) => {
    try {
      const result = queryRunApiService.get(String(req.params.caseId), String(req.params.queryRunId));
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/activate", (req, res) => {
    try {
      const cardId = typeof req.body?.cardId === "string" ? req.body.cardId : "";
      const result = queryRunApiService.activate(String(req.params.caseId), String(req.params.queryRunId), cardId);
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/select", async (req, res) => {
    try {
      const result = await queryRunApiService.select(
        String(req.params.caseId),
        String(req.params.queryRunId),
        String(req.params.conversationId),
        req.body?.openWireshark === true
      );
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/packets", async (req, res) => {
    try {
      const result = await queryRunApiService.packets(String(req.params.caseId), String(req.params.queryRunId), String(req.params.conversationId));
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/open-wireshark", async (req, res) => {
    try {
      const conversationId = String(req.body?.conversationId || "");
      const result = await queryRunApiService.openWireshark(String(req.params.caseId), String(req.params.queryRunId), conversationId);
      if (!result.ok) return res.status(result.status).json({ error: result.error });
      return res.json(result.data);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/evidence/open", async (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const pcapFilename = String(req.body?.pcapFilename || "");
      const displayFilter = String(req.body?.displayFilter || "");
      const frameNumber = Number(req.body?.frameNumber);
      const queryRunId = String(req.body?.queryRunId || "");
      const cardId = String(req.body?.cardId || "");
      if (!pcapFilename || !displayFilter) return res.status(400).json({ error: "pcapFilename and displayFilter are required" });
      const capture = graph.captures.find((item) => item.pcapFilename === pcapFilename);
      if (!capture?.pcapFilename) return res.status(404).json({ error: "capture file not found" });
      const result = await evidenceOpenService.openEvidence(graph, {
        pcapFilename: capture.pcapFilename,
        displayFilter,
        frameNumber: Number.isFinite(frameNumber) ? frameNumber : undefined,
        queryRunId: queryRunId || undefined,
        cardId: cardId || undefined
      });
      if (!result) return res.status(404).json({ error: "capture file not found" });
      return res.json(result.wireshark);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId", async (req, res) => {
    try {
      return res.json(await loadGraphWithInsights(String(req.params.caseId)));
    } catch {
      return res.status(404).json({ error: "case not found" });
    }
  });

  router.get("/cases/:caseId/chat", (req, res) => {
    const caseId = safePathPart(String(req.params.caseId));
    const chatPath = path.join(caseDirectory(caseId), "chat.json");
    if (!existsSync(chatPath)) return res.json({ messages: [] });
    try {
      return res.json({ messages: JSON.parse(readFileSync(chatPath, "utf8")) });
    } catch {
      return res.json({ messages: [] });
    }
  });

  router.put("/cases/:caseId/chat", (req, res) => {
    const caseId = safePathPart(String(req.params.caseId));
    const { messages } = req.body;
    if (!Array.isArray(messages)) return res.status(400).json({ error: "messages must be an array" });
    const clean = messages
      .map((m: Record<string, unknown>) => ({ ...m, streaming: false }))
      .filter((m: Record<string, unknown>) => (typeof m.content === "string" && m.content.trim()) || (Array.isArray(m.thoughts) && m.thoughts.length))
      .slice(-200);
    try {
      writeFileSync(path.join(caseDirectory(caseId), "chat.json"), JSON.stringify(clean, null, 2));
      return res.json({ ok: true });
    } catch {
      return res.status(500).json({ error: "failed to save chat" });
    }
  });

  // TCP Stream 端点
  router.get("/cases/:caseId/tcp-streams", async (req, res) => {
    const caseId = safePathPart(String(req.params.caseId));
    const graph = await loadGraph(caseId);
    if (!graph) return res.status(404).json({ error: "case not found" });
    const nodeId = req.query.nodeId as string | undefined;
    const captures = nodeId
      ? graph.captures.filter(c => c.nodeId === nodeId && c.pcapFilename)
      : graph.captures.filter(c => c.pcapFilename);
    if (!captures.length) return res.json({ streams: [] });
    try {
      const result = await listTcpStreamsWithMcp({
        captures: captures.map(c => ({ nodeId: c.nodeId, name: c.pcapFilename!, pcapPath: path.join(caseDirectory(caseId), "captures", c.pcapFilename!) }))
      });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });

  router.get("/cases/:caseId/tcp-streams/:streamIndex/content", async (req, res) => {
    const caseId = safePathPart(String(req.params.caseId));
    const streamIndex = parseInt(req.params.streamIndex, 10);
    if (isNaN(streamIndex)) return res.status(400).json({ error: "invalid streamIndex" });
    const graph = await loadGraph(caseId);
    if (!graph) return res.status(404).json({ error: "case not found" });
    const nodeId = req.query.nodeId as string | undefined;
    const capture = nodeId
      ? graph.captures.find(c => c.nodeId === nodeId && c.pcapFilename)
      : graph.captures.find(c => c.pcapFilename);
    if (!capture?.pcapFilename) return res.status(404).json({ error: "no capture found" });
    try {
      const result = await followTcpStreamWithMcp({
        pcapPath: path.join(caseDirectory(caseId), "captures", capture.pcapFilename),
        streamIndex,
        format: (req.query.format as "ascii" | "raw") || "ascii"
      });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });

  router.get("/cases/:caseId/analysis-runs/:runId", (req, res) => {
    try {
      return res.json(readAnalysisRunSnapshot(String(req.params.caseId), String(req.params.runId)));
    } catch {
      return res.status(404).json({ error: "analysis run not found" });
    }
  });

  router.get("/cases/:caseId/report", (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      return res.json({ markdown: buildCaseReportMarkdown(graph) });
    } catch {
      return res.status(404).json({ error: "case not found" });
    }
  });

  router.post("/cases/:caseId/agent", async (req, res) => {
    let graph: CaseGraph;
    try {
      graph = await loadGraphWithInsights(String(req.params.caseId));
    } catch {
      return res.status(404).json({ error: "case not found" });
    }

    const parsedRequest = AgentRequestSchema.safeParse(req.body || {});
    if (!parsedRequest.success) return res.status(400).json({ error: parsedRequest.error.flatten() });
    const requestedProfileId = parsedRequest.data.profileId;
    if (requestedProfileId && !activateLlmProfile(requestedProfileId)) {
      return res.status(404).json({ error: "llm profile not found" });
    }

    try {
      const result = await agentRuntimeService.run(graph, parsedRequest.data);
      return res.json(result.answer);
    } catch (error) {
      return res.status(502).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/agent/stream", async (req, res) => {
    let graph: CaseGraph;
    try {
      graph = await loadGraphWithInsights(String(req.params.caseId));
    } catch {
      return res.status(404).json({ error: "case not found" });
    }

    const parsedRequest = AgentRequestSchema.safeParse(req.body || {});
    if (!parsedRequest.success) return res.status(400).json({ error: parsedRequest.error.flatten() });
    const requestedProfileId = parsedRequest.data.profileId;
    if (requestedProfileId && !activateLlmProfile(requestedProfileId)) {
      return res.status(404).json({ error: "llm profile not found" });
    }

    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    try {
      await agentRuntimeService.stream(graph, parsedRequest.data, {
        event: (event, data) => writeStreamEvent(res, event, data),
        thought: (text) => writeStreamEvent(res, "thought", { text }),
        delta: (text) => writeStreamEvent(res, "delta", { text }),
        done: (answer) => writeStreamEvent(res, "done", answer),
        error: (error) => writeStreamEvent(res, "error", { error })
      });
    } catch (error) {
      writeStreamEvent(res, "error", { error: error instanceof Error ? error.message : String(error) });
    }
    return res.end();
  });

  return router;
}
