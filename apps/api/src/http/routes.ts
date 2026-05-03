import { mkdirSync } from "node:fs";
import path from "node:path";
import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import {
  CaptureNodeSchema,
  CaseSpecSchema,
  MappingHintSchema,
  QueryRunInputSchema,
  TimeOffsetHintSchema,
  type AgentAnswer,
  type CaseGraph,
  type EvidenceCard,
  type QueryRun,
} from "../../../../packages/shared/src/index.js";
import { runAgentCompatibilityCheck, runPcapTroubleshootingAgent } from "../agents/runtime.js";
import { learnFromAgentRun, loadLearnedPatterns } from "../services/patternLearner.js";
import { apiConfig } from "../config.js";
import { getCaptureTimeRangeWithMcp, getConversationPacketsWithMcp, listDnsPacketsWithMcp, listHttpPacketsWithMcp, listIcmpEventsWithMcp, listTcpResetsWithMcp, listTcpRetransmissionsWithMcp, listTcpZeroWindowWithMcp, listTlsPacketsWithMcp, listUdpPacketsWithMcp, queryPacketsWithMcp } from "../mcp/tsharkQueryClient.js";
import { createPacketPairAnswer, createProtocolQueryAnswer, groupPacketPairs, noCaptureAnswer, pairGroupFromPackets, pairKey, protocolPacketCard } from "../protocolAdapters/builders.js";
import { createDnsAdapter } from "../protocolAdapters/dns.js";
import { createHttpAdapter } from "../protocolAdapters/http.js";
import { createIcmpAdapter } from "../protocolAdapters/icmp.js";
import { createTcpAdapters } from "../protocolAdapters/tcp.js";
import { createTlsAdapter } from "../protocolAdapters/tls.js";
import { protocolAdapterErrorMessage, protocolAdapterErrorStatus, runProtocolAdapter, type ProtocolAdapter, type ProtocolAdapterContext } from "../protocolAdapters/types.js";
import { createUdpAdapter } from "../protocolAdapters/udp.js";
import { stripPayload } from "./capturePreprocess.js";
import { addCapture, capturesDirectory, createEmptyCase, deleteCases, listCaseSummaries, readAnalysisRunSnapshot, readCaseGraph, safePathPart, writeCaseGraph } from "./caseStore.js";
import { activateLlmProfile, deleteLlmProfiles, getLlmSettings, listLlmProfiles, parseProviderData, saveLlmProfile, saveLlmSettings } from "./llmSettings.js";
import { buildCaseReportMarkdown } from "./reportBuilder.js";
import { createAgentAnswerService } from "../services/agentAnswerService.js";
import { createEvidenceOpenService } from "../services/evidenceOpenService.js";
import { createPlannerService, executeChain } from "../services/plannerService.js";
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
const { recordPlannerRun, recordAnswerRun, recordErrorRun, recordMcpRun, recordQueryRunMcp } = toolRunService;
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
  fallbackAgentAnswer,
  troubleshootingScopeAnswer,
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

const setCaseGraph = (caseId: string, graph: CaseGraph) => cases.set(caseId, graph);
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
const plannerService = createPlannerService({
  fallbackPatterns: apiConfig.planner.fallbackPatterns,
  hasLlmApiKey: () => Boolean(apiConfig.llm.apiKey),
  isProtocolStatisticsQuestion,
  shouldApplyCorrelationContext,
  activeCorrelationNeedsContext,
  shouldCorrelateCaptures,
  shouldCreateQueryRun,
  usageHelpAnswer,
  deterministicStatisticsAnswer,
  applyCorrelationContextAndRerun,
  createCaptureCorrelationQueryRun,
  runProtocolEventQuery: async (graph, question) => {
    const matching = protocolAdapters.filter((candidate) => candidate.match(question));
    if (!matching.length) {
      const learnedPatterns = loadLearnedPatterns();
      const adapterResult = await runProtocolAdapter(protocolAdapters, graph, question, learnedPatterns);
      if (adapterResult) return { status: adapterResult.adapter.status, answer: adapterResult.answer };
      if (apiConfig.llm.apiKey) {
        try {
          const agentAnswer = await runPcapTroubleshootingAgent({ graph, question });
          const adapterIds = protocolAdapters.map((a) => a.id);
          learnFromAgentRun(question, agentAnswer.toolCalls || [], adapterIds).catch(() => {});
          return { status: "agent_fallback", answer: agentAnswer };
        } catch {
          return null;
        }
      }
      return null;
    }
    if (matching.length === 1) {
      const answer = await matching[0].run(graph, question);
      return { status: matching[0].status, answer };
    }
    const results = await Promise.all(matching.map(async (adapter) => ({ adapter, answer: await adapter.run(graph, question) })));
    const combinedAnswer: AgentAnswer = {
      answer: results.map((r) => r.answer.answer).join("\n\n---\n\n"),
      thoughts: results.flatMap((r) => r.answer.thoughts || []),
      evidenceCards: results.flatMap((r) => r.answer.evidenceCards || []),
      actions: results.flatMap((r) => r.answer.actions || []),
      evidenceIds: results.flatMap((r) => r.answer.evidenceIds),
      packetIds: results.flatMap((r) => r.answer.packetIds),
      sessionLinkIds: results.flatMap((r) => r.answer.sessionLinkIds),
      findingIds: results.flatMap((r) => r.answer.findingIds),
      missingContext: results.flatMap((r) => r.answer.missingContext),
      confidence: results.every((r) => r.answer.confidence === "certain") ? "certain" : results.some((r) => r.answer.confidence === "low" || r.answer.confidence === "needs_context") ? "low" : "high",
      suggestedActions: results.flatMap((r) => r.answer.suggestedActions),
      suggestedQueries: results.flatMap((r) => r.answer.suggestedQueries || []),
      handoffAgent: results[results.length - 1]?.answer.handoffAgent
    };
    return { status: "deterministic_multi_protocol", answer: combinedAnswer };
  },
  createTcpSessionQueryRun: async (graph, question) => {
    const queryInput = QueryRunInputSchema.parse({ ...inferQueryRunInput(question, graph), question });
    const nextGraph = await createQueryRun(graph, queryInput);
    return queryRunAnswer(nextGraph, nextGraph.activeQueryRunId || "");
  },
  selectedSessionProblemAnswer,
  activeQueryRunAnswer,
  reportAnswer,
  troubleshootingScopeAnswer,
  runLlmExplain: async (graph, question) => {
    const answer = await runPcapTroubleshootingAgent({ graph, question });
    return answer;
  }
});
const {
  shouldAnswerUsageHelp,
  shouldAnswerActiveQueryRun,
  shouldExplainSelectedSessionProblem,
  shouldAskForTroubleshootingScope,
  planUserIntent,
  planChain,
  executeAgentIntentPlan,
  executeChainStep
} = plannerService;

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
    const caseId = String(req.params.caseId);
    try {
      const graph = loadGraph(caseId);
      const inferred = inferQueryRunInput(String(req.body?.question || ""), graph);
      const parsed = QueryRunInputSchema.safeParse({ ...inferred, ...(req.body || {}) });
      if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
      const nextGraph = await createQueryRun(graph, parsed.data);
      const queryRun = nextGraph.queryRuns.find((run) => run.queryRunId === nextGraph.activeQueryRunId);
      return res.status(201).json({ graph: nextGraph, queryRun });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId/query-runs/:queryRunId", (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const queryRun = graph.queryRuns.find((run) => run.queryRunId === String(req.params.queryRunId));
      if (!queryRun) return res.status(404).json({ error: "query run not found" });
      return res.json({ queryRun });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/activate", (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const queryRunId = String(req.params.queryRunId);
      const cardId = typeof req.body?.cardId === "string" ? req.body.cardId : "";
      const queryRun = graph.queryRuns.find((run) => run.queryRunId === queryRunId);
      if (!queryRun) return res.status(404).json({ error: "query run not found" });
      const nextGraph: CaseGraph = {
        ...graph,
        activeQueryRunId: queryRunId,
        queryRuns: graph.queryRuns.map((run) => run.queryRunId === queryRunId && cardId ? { ...run, selectedEvidenceCardId: cardId } : run)
      };
      writeCaseGraph(nextGraph);
      cases.set(graph.spec.caseId, nextGraph);
      return res.json(nextGraph);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/select", async (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const selected = await selectConversation(graph, String(req.params.queryRunId), String(req.params.conversationId));
      if (selected.status === "query_not_found") return res.status(404).json({ error: "query run not found" });
      if (selected.status === "conversation_not_found") return res.status(404).json({ error: "conversation not found" });
      if (selected.status === "capture_not_found") return res.status(404).json({ error: "capture file not found" });
      const shouldOpenWireshark = req.body?.openWireshark === true;
      const wireshark = shouldOpenWireshark && selected.conversation.pcapFilename
        ? await evidenceOpenService.openConversation(selected.graph, selected.queryRun, selected.conversation, "打开选中 TCP session 的 Wireshark filter。")
        : null;
      return res.json({ graph: selected.graph, queryRun: selected.queryRun, wireshark });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/packets", async (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const queryRun = graph.queryRuns.find((run) => run.queryRunId === String(req.params.queryRunId));
      if (!queryRun) return res.status(404).json({ error: "query run not found" });
      const conversation = queryRun.conversations.find((item) => item.conversationId === String(req.params.conversationId));
      if (!conversation) return res.status(404).json({ error: "conversation not found" });
      const capture = graph.captures.find((item) => item.nodeId === conversation.nodeId && item.pcapFilename === conversation.pcapFilename);
      if (!capture?.pcapFilename) return res.status(404).json({ error: "capture file not found" });
      const result = await getConversationPacketsWithMcp({
        capture: {
          nodeId: capture.nodeId,
          name: capture.name,
          pcapFilename: capture.pcapFilename,
          pcapPath: path.join(capturesDirectory(graph.spec.caseId), capture.pcapFilename)
        },
        displayFilter: conversation.displayFilter,
        limit: apiConfig.query.conversationPacketLimit
      });
      return res.json(result);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/query-runs/:queryRunId/open-wireshark", async (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      const queryRun = graph.queryRuns.find((run) => run.queryRunId === String(req.params.queryRunId));
      if (!queryRun) return res.status(404).json({ error: "query run not found" });
      const conversationId = String(req.body?.conversationId || queryRun.selectedConversationId || "");
      const conversation = queryRun.conversations.find((item) => item.conversationId === conversationId);
      if (!conversation) return res.status(404).json({ error: "conversation not found" });
      const capture = graph.captures.find((item) => item.nodeId === conversation.nodeId && item.pcapFilename === conversation.pcapFilename);
      if (!capture?.pcapFilename) return res.status(404).json({ error: "capture file not found" });
      const wireshark = await evidenceOpenService.openConversation(graph, queryRun, conversation);
      if (!wireshark) return res.status(404).json({ error: "capture file not found" });
      return res.json(wireshark);
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
      return res.json({ ...result.wireshark, graph: result.graph });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/cases/:caseId", (req, res) => {
    try {
      return res.json(loadGraph(String(req.params.caseId)));
    } catch {
      return res.status(404).json({ error: "case not found" });
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
      graph = loadGraph(String(req.params.caseId));
    } catch {
      return res.status(404).json({ error: "case not found" });
    }

    const parsedRequest = AgentRequestSchema.safeParse(req.body || {});
    if (!parsedRequest.success) return res.status(400).json({ error: parsedRequest.error.flatten() });
    const requestedProfileId = parsedRequest.data.profileId;
    if (requestedProfileId && !activateLlmProfile(requestedProfileId)) {
      return res.status(404).json({ error: "llm profile not found" });
    }
    const requestStartedAt = Date.now();
    const plannerStartedAt = Date.now();
    const plan = await planUserIntent(graph, parsedRequest.data.question);
    const plannerDurationMs = Date.now() - plannerStartedAt;
    try {
      const plannedResult = await executeAgentIntentPlan(graph, parsedRequest.data.question, plan);
      if (plannedResult) {
        const answer = answerWithPlannerThought(plannedResult.answer, plan);
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordAnswerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannedResult.status, answer, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: plannedResult.status,
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(answer);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
      recordErrorRun(graph.spec.caseId, parsedRequest.data.question, plan, `${plan.intent}_error`, error, Date.now() - requestStartedAt);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: `${plan.intent}_error`,
        lastError: message,
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.status(502).json({ error: message });
    }
    if (apiConfig.llm.apiKey && plan.intent === "llm_explain") {
      try {
        const answer = await runPcapTroubleshootingAgent({ graph, question: buildAgentQuestion(parsedRequest.data) });
        const plannedAnswer = answerWithPlannerThought(answer, plan);
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordAnswerRun(graph.spec.caseId, parsedRequest.data.question, plan, "success", plannedAnswer, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "success",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(plannedAnswer);
      } catch (error) {
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordErrorRun(graph.spec.caseId, parsedRequest.data.question, plan, "error", error, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "error",
          lastError: error instanceof Error ? error.message : String(error),
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.status(502).json({ error: `LLM 调用失败：${error instanceof Error ? error.message : String(error)}` });
      }
    }
    if (shouldAnswerUsageHelp(parsedRequest.data.question)) {
      const answer = usageHelpAnswer();
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "usage_help",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(answer);
    }
    const deterministicAnswer = await deterministicStatisticsAnswer(graph, parsedRequest.data.question);
    if (deterministicAnswer) {
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "deterministic_statistics",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(deterministicAnswer);
    }
    if (shouldApplyCorrelationContext(parsedRequest.data.question, graph)) {
      try {
        const answer = await applyCorrelationContextAndRerun(graph, parsedRequest.data.question);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "correlation_context_applied",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(answer);
      } catch (error) {
        return res.status(502).json({ error: `关联上下文应用失败：${error instanceof Error ? error.message : String(error)}` });
      }
    }
    if (shouldCorrelateCaptures(parsedRequest.data.question)) {
      try {
        const answer = await createCaptureCorrelationQueryRun(graph, parsedRequest.data.question);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "capture_correlation",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(answer);
      } catch (error) {
        return res.status(502).json({ error: `多文件关联失败：${error instanceof Error ? error.message : String(error)}` });
      }
    }
    try {
      const adapterResult = await runProtocolAdapter(protocolAdapters, graph, parsedRequest.data.question);
      if (adapterResult) {
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: adapterResult.adapter.status,
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(adapterResult.answer);
      }
    } catch (error) {
      return res.status(502).json({ error: protocolAdapterErrorMessage(error) });
    }
    if (shouldCreateQueryRun(parsedRequest.data.question)) {
      try {
        const queryInput = QueryRunInputSchema.parse({ ...inferQueryRunInput(parsedRequest.data.question, graph), question: parsedRequest.data.question });
        const nextGraph = await createQueryRun(graph, queryInput);
        const answer = queryRunAnswer(nextGraph, nextGraph.activeQueryRunId || "");
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "query_run",
          lastError: "",
          lastCaseId: nextGraph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        return res.json(answer);
      } catch (error) {
        return res.status(502).json({ error: `QueryRun 创建失败：${error instanceof Error ? error.message : String(error)}` });
      }
    }
    if (graph.queryRuns.length && shouldExplainSelectedSessionProblem(parsedRequest.data.question)) {
      const answer = selectedSessionProblemAnswer(graph);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "selected_session_diagnosis",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(answer);
    }
    if (graph.queryRuns.length && shouldExplainSelectedSessionProblem(parsedRequest.data.question)) {
      const answer = selectedSessionProblemAnswer(graph);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "selected_session_diagnosis",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
      writeStreamEvent(res, "delta", { text: answer.answer });
      writeStreamEvent(res, "done", answer);
      return res.end();
    }

    if (graph.queryRuns.length && shouldAnswerActiveQueryRun(parsedRequest.data.question)) {
      const answer = activeQueryRunAnswer(graph, parsedRequest.data.question);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "query_run_diagnosis",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(answer);
    }
    if (shouldAskForTroubleshootingScope(parsedRequest.data.question, graph)) {
      const answer = troubleshootingScopeAnswer();
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "needs_query_scope",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(answer);
    }
    const question = buildAgentQuestion(parsedRequest.data);
    const fallback = fallbackAgentAnswer(graph);

    if (!apiConfig.llm.apiKey) {
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "fallback_no_key",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(fallback);
    }

    try {
      const answer = await runPcapTroubleshootingAgent({ graph, question });
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "success",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.json(answer);
    } catch (error) {
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "error",
        lastError: error instanceof Error ? error.message : String(error),
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      return res.status(502).json({ error: `LLM 调用失败：${error instanceof Error ? error.message : String(error)}` });
    }
  });

  router.post("/cases/:caseId/agent/stream", async (req, res) => {
    let graph: CaseGraph;
    try {
      graph = loadGraph(String(req.params.caseId));
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

    const requestStartedAt = Date.now();
    const plannerStartedAt = Date.now();
    const chainPlan = await planChain(graph, parsedRequest.data.question, (text) => writeStreamEvent(res, "thought", { text }));
    const plannerDurationMs = Date.now() - plannerStartedAt;
    const stepSummary = chainPlan.steps.map((step) => `${step.intent}(${step.purpose})`).join(" → ");
    writeStreamEvent(res, "thought", {
      text: `Chain Planner 识别：${chainPlan.planKind}（${chainPlan.confidence}）${stepSummary}${chainPlan.reason ? `，${chainPlan.reason}` : ""}`
    });

    if (chainPlan.planKind === "chain") {
      writeStreamEvent(res, "chain_start", { chainId: chainPlan.chainId, stepCount: chainPlan.steps.length });
      try {
        const { results, finalAnswer } = await executeChain(graph, chainPlan, (currentGraph, intent, params) => executeChainStep(currentGraph, parsedRequest.data.question, intent, params), {
          onStepStart: (step, index, total) => {
            writeStreamEvent(res, "step_start", { stepId: step.stepId, intent: step.intent, purpose: step.purpose, index, total });
            writeStreamEvent(res, "thought", { text: `步骤 ${index + 1}/${total}：${step.purpose}` });
          },
          onStepDone: (step, result, index, total) => {
            writeStreamEvent(res, "step_done", { stepId: step.stepId, status: result.status, summary: result.answer.answer.slice(0, 200), index, total });
          },
          onError: (step, error, index, total) => {
            writeStreamEvent(res, "step_done", { stepId: step.stepId, status: "error", summary: `步骤失败：${error instanceof Error ? error.message : String(error)}`, index, total });
          }
        }, () => loadGraph(graph.spec.caseId));
        const hasLlmStep = chainPlan.steps.some((s) => s.intent === "llm_explain");
        let enrichedAnswer = finalAnswer;
        if (!hasLlmStep && apiConfig.llm.apiKey) {
          writeStreamEvent(res, "thought", { text: "综合解读证据，生成诊断结论..." });
          try {
            const synthesisQuestion = `基于以下分析链结果，综合解读异常并给出诊断结论：\n${finalAnswer.answer}`;
            const freshGraph = loadGraph(graph.spec.caseId);
            const llmAnswer = await runPcapTroubleshootingAgent({ graph: freshGraph, question: synthesisQuestion });
            enrichedAnswer = {
              ...finalAnswer,
              answer: `${finalAnswer.answer}\n\n---\n### 综合解读\n${llmAnswer.answer}`,
              thoughts: [...(finalAnswer.thoughts || []), ...(llmAnswer.thoughts || [])],
              evidenceCards: [...(finalAnswer.evidenceCards || []), ...(llmAnswer.evidenceCards || [])],
              suggestedQueries: llmAnswer.suggestedQueries,
              handoffAgent: llmAnswer.handoffAgent
            };
          } catch {
            // LLM 解读失败不影响已有结果
          }
        }
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, { intent: chainPlan.steps[0].intent, confidence: chainPlan.confidence, reason: chainPlan.reason, missingContext: chainPlan.missingContext }, plannerDurationMs);
        recordAnswerRun(graph.spec.caseId, parsedRequest.data.question, { intent: chainPlan.steps[0].intent, confidence: chainPlan.confidence, reason: chainPlan.reason, missingContext: chainPlan.missingContext }, "chain_complete", enrichedAnswer, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "chain_complete",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "chain_done", { chainId: chainPlan.chainId, summaries: results.map((r) => ({ stepId: r.stepId, status: r.status })) });
        writeStreamEvent(res, "delta", { text: enrichedAnswer.answer });
        writeStreamEvent(res, "done", enrichedAnswer);
        return res.end();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        recordErrorRun(graph.spec.caseId, parsedRequest.data.question, { intent: chainPlan.steps[0].intent, confidence: chainPlan.confidence, reason: chainPlan.reason, missingContext: chainPlan.missingContext }, "chain_error", error, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "chain_error",
          lastError: message,
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "error", { error: message });
        return res.end();
      }
    }

    const plan = { intent: chainPlan.steps[0].intent, confidence: chainPlan.confidence, reason: chainPlan.reason, missingContext: chainPlan.missingContext };
    try {
      const plannedResult = await executeAgentIntentPlan(graph, parsedRequest.data.question, plan);
      if (plannedResult) {
        const answer = answerWithPlannerThought(plannedResult.answer, plan);
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordAnswerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannedResult.status, answer, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: plannedResult.status,
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
        writeStreamEvent(res, "delta", { text: answer.answer });
        writeStreamEvent(res, "done", answer);
        return res.end();
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
      recordErrorRun(graph.spec.caseId, parsedRequest.data.question, plan, `${plan.intent}_error`, error, Date.now() - requestStartedAt);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: `${plan.intent}_error`,
        lastError: message,
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "error", { error: message });
      return res.end();
    }
    if (apiConfig.llm.apiKey && plan.intent === "llm_explain") {
      try {
        const answer = await runPcapTroubleshootingAgent({
          graph,
          question: buildAgentQuestion(parsedRequest.data),
          onTrace: (text) => writeStreamEvent(res, "thought", { text })
        });
        const plannedAnswer = answerWithPlannerThought(answer, plan);
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordAnswerRun(graph.spec.caseId, parsedRequest.data.question, plan, "success", plannedAnswer, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "success",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        plannedAnswer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
        for (let index = 0; index < plannedAnswer.answer.length; index += 24) {
          writeStreamEvent(res, "delta", { text: plannedAnswer.answer.slice(index, index + 24) });
        }
        writeStreamEvent(res, "done", plannedAnswer);
      } catch (error) {
        const message = `LLM 调用失败：${error instanceof Error ? error.message : String(error)}`;
        recordPlannerRun(graph.spec.caseId, parsedRequest.data.question, plan, plannerDurationMs);
        recordErrorRun(graph.spec.caseId, parsedRequest.data.question, plan, "error", error, Date.now() - requestStartedAt);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "error",
          lastError: message,
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "error", { error: message });
      }
      return res.end();
    }

    if (shouldAnswerUsageHelp(parsedRequest.data.question)) {
      const answer = usageHelpAnswer();
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "usage_help",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
      writeStreamEvent(res, "delta", { text: answer.answer });
      writeStreamEvent(res, "done", answer);
      return res.end();
    }

    const deterministicAnswer = await deterministicStatisticsAnswer(graph, parsedRequest.data.question);
    if (deterministicAnswer) {
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "deterministic_statistics",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "thought", { text: "识别为确定性统计问题，直接调用对应统计工具，不进入 LLM 自由推理。" });
      writeStreamEvent(res, "delta", { text: deterministicAnswer.answer });
      writeStreamEvent(res, "done", deterministicAnswer);
      return res.end();
    }

    if (shouldApplyCorrelationContext(parsedRequest.data.question, graph)) {
      writeStreamEvent(res, "thought", { text: "识别为多文件关联后的上下文补充，准备写入 hint 并重跑关联。" });
      try {
        const answer = await applyCorrelationContextAndRerun(graph, parsedRequest.data.question);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "correlation_context_applied",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
        writeStreamEvent(res, "delta", { text: answer.answer });
        writeStreamEvent(res, "done", answer);
      } catch (error) {
        const message = `关联上下文应用失败：${error instanceof Error ? error.message : String(error)}`;
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "correlation_context_error",
          lastError: message,
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "error", { error: message });
      }
      return res.end();
    }

    if (shouldCorrelateCaptures(parsedRequest.data.question)) {
      writeStreamEvent(res, "thought", { text: "识别为多文件/多节点链路关联问题，创建 QueryRun。" });
      writeStreamEvent(res, "thought", { text: "调用 tshark-query MCP 列出 TCP conversations，并按 exact tuple / mapping hint / time offset 关联。" });
      try {
        const answer = await createCaptureCorrelationQueryRun(graph, parsedRequest.data.question);
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "capture_correlation",
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "delta", { text: answer.answer });
        writeStreamEvent(res, "done", answer);
      } catch (error) {
        const message = `多文件关联失败：${error instanceof Error ? error.message : String(error)}`;
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "capture_correlation_error",
          lastError: message,
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "error", { error: message });
      }
      return res.end();
    }

    try {
      const learnedPatterns = loadLearnedPatterns();
      const adapterResult = await runProtocolAdapter(protocolAdapters, graph, parsedRequest.data.question, learnedPatterns);
      if (adapterResult) {
        adapterResult.answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: adapterResult.adapter.status,
          lastError: "",
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "delta", { text: adapterResult.answer.answer });
        writeStreamEvent(res, "done", adapterResult.answer);
        return res.end();
      }
    } catch (error) {
      const message = protocolAdapterErrorMessage(error);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: protocolAdapterErrorStatus(),
        lastError: message,
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "error", { error: message });
      return res.end();
    }

    if (shouldCreateQueryRun(parsedRequest.data.question)) {
      writeStreamEvent(res, "thought", { text: "识别为访问链路查询，创建 QueryRun。" });
      writeStreamEvent(res, "thought", { text: "调用 tshark-query MCP 生成 display filter 并查询通讯对。" });
      try {
        const queryInput = QueryRunInputSchema.parse({ ...inferQueryRunInput(parsedRequest.data.question, graph), question: parsedRequest.data.question });
        const nextGraph = await createQueryRun(graph, queryInput);
        const answer = queryRunAnswer(nextGraph, nextGraph.activeQueryRunId || "");
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "query_run",
          lastError: "",
          lastCaseId: nextGraph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "delta", { text: answer.answer });
        writeStreamEvent(res, "done", answer);
      } catch (error) {
        const message = `QueryRun 创建失败：${error instanceof Error ? error.message : String(error)}`;
        Object.assign(agentRuntimeStatus, {
          lastRunAt: new Date().toISOString(),
          lastStatus: "query_run_error",
          lastError: message,
          lastCaseId: graph.spec.caseId,
          lastModel: apiConfig.llm.model,
          lastBaseURL: apiConfig.llm.baseURL
        });
        writeStreamEvent(res, "error", { error: message });
      }
      return res.end();
    }

    if (graph.queryRuns.length && shouldAnswerActiveQueryRun(parsedRequest.data.question)) {
      const answer = activeQueryRunAnswer(graph, parsedRequest.data.question);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "query_run_diagnosis",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "thought", { text: "识别为当前访问链路问题，读取 active QueryRun。" });
      writeStreamEvent(res, "thought", { text: "使用选中通讯对的确定性诊断结果回答，不让模型泛化判断。" });
      writeStreamEvent(res, "delta", { text: answer.answer });
      writeStreamEvent(res, "done", answer);
      return res.end();
    }

    if (shouldAskForTroubleshootingScope(parsedRequest.data.question, graph)) {
      const answer = troubleshootingScopeAnswer();
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "needs_query_scope",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      answer.thoughts?.forEach((thought) => writeStreamEvent(res, "thought", { text: thought }));
      writeStreamEvent(res, "delta", { text: answer.answer });
      writeStreamEvent(res, "done", answer);
      return res.end();
    }

    const question = buildAgentQuestion(parsedRequest.data);
    writeStreamEvent(res, "thought", { text: `未命中确定性分流，进入 Agents SDK 解释流程；case=${graph.spec.caseId}，activeQueryRun=${graph.activeQueryRunId || "无"}。` });

    if (!apiConfig.llm.apiKey) {
      const fallback = fallbackAgentAnswer(graph);
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "fallback_no_key",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "delta", { text: fallback.answer });
      writeStreamEvent(res, "done", fallback);
      return res.end();
    }

    try {
      const answer = await runPcapTroubleshootingAgent({
        graph,
        question,
        onTrace: (text) => writeStreamEvent(res, "thought", { text })
      });
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "success",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      const adapterIds = protocolAdapters.map((a) => a.id);
      learnFromAgentRun(parsedRequest.data.question, answer.toolCalls || [], adapterIds).catch(() => {});
      for (let index = 0; index < answer.answer.length; index += 24) {
        writeStreamEvent(res, "delta", { text: answer.answer.slice(index, index + 24) });
      }
      writeStreamEvent(res, "done", answer);
      return res.end();
    } catch (error) {
      const message = `LLM 调用失败：${error instanceof Error ? error.message : String(error)}`;
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "error",
        lastError: message,
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
      writeStreamEvent(res, "error", { error: message });
      return res.end();
    }
  });

  return router;
}
