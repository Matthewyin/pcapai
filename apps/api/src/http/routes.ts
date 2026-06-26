import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
import { runAgentCompatibilityCheck } from "../agents/runtime.js";
import { rfcIndexStatus, searchRfc } from "../services/rfcRagService.js";
import { startDownload, getDownloadStatus, cancelDownload, deleteDownloadedDb } from "../services/rfcDownloadService.js";
import { listStatus as listMcpStatus, upsertServer, removeServer, toggleServer, loadServers as loadMcpServers, type McpServerConfig } from "../mcp/mcpRegistry.js";
import { fieldNotesIndexStatus, listAllFieldNotes, getFieldNote, verifyFieldNote, disputeFieldNote, createFieldNote, deleteFieldNote, extractPacketFeatures, searchFieldNotes } from "../services/fieldNotesService.js";
import { listSkills, listSkillsWithStatus, getSkill, createSkill, deleteSkill, toggleSkill, skillsIndexStatus } from "../services/skillsService.js";
import { deleteLearnedPattern, listLearnedPatterns } from "../services/patternLearner.js";
import { apiConfig } from "../config.js";
import { getCaptureTimeRangeWithMcp, listTcpStreamsWithMcp, followTcpStreamWithMcp } from "../mcp/tsharkQueryClient.js";
import { stripPayload } from "./capturePreprocess.js";
import { addCapture, capturesDirectory, caseDirectory, createEmptyCase, deleteCases, listCaseSummaries, readAnalysisRunSnapshot, readCaseGraph, safePathPart, writeCaseGraph } from "./caseStore.js";
import { activateLlmProfile, deleteLlmProfiles, getLlmSettings, listLlmProfiles, parseProviderData, saveLlmProfile, saveLlmSettings } from "./llmSettings.js";
import { buildCaseReportMarkdown } from "./reportBuilder.js";
import { extractProtocolAnomalies } from "../services/tcpPreprocessor.js";
import { composeServices } from "./composeServices.js";

const cases = new Map<string, CaseGraph>();

// per-case 互斥锁：agent 运行会跨多次 read-modify-write（含 chain step 间的 reloadGraph 和
// 末尾 syncMemoryFromQueryRuns），整个运行周期是一个逻辑临界区。并发 agent run（用户连发两条
// 消息、或 SSE 还在跑时又发一条）会在各自的 reloadGraph 互相覆盖 QueryRun。
// 仅串行化 agent run 入口，不覆盖同步 handler（PUT hints 等）——它们快且改不同字段，风险低。
const caseRunLocks = new Map<string, Promise<unknown>>();
function withCaseRunLock<T>(caseId: string, task: () => Promise<T>): Promise<T> {
  const previous = caseRunLocks.get(caseId) || Promise.resolve();
  const next = previous.then(task, task);
  caseRunLocks.set(caseId, next);
  // 用 then(_, cleanup) 而非 finally(cleanup)：前者不产生额外 Promise，
  // 后者返回的新 Promise 会继承 next 的 rejection，task 一旦 reject 会触发 unhandledRejection。
  next.then(
    () => {
      if (caseRunLocks.get(caseId) === next) caseRunLocks.delete(caseId);
    },
    () => {
      if (caseRunLocks.get(caseId) === next) caseRunLocks.delete(caseId);
    }
  );
  return next;
}

// 简化 LRU：重新插入刷新热度，超过上限淘汰最久未写入的 case，防止长期运行内存无限增长
function cacheCase(caseId: string, graph: CaseGraph) {
  cases.delete(caseId);
  cases.set(caseId, graph);
  if (cases.size > apiConfig.caseCacheLimit) {
    const oldest = cases.keys().next().value;
    if (oldest !== undefined) cases.delete(oldest);
  }
}

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
  cacheCase(caseId, graph);
  return graph;
}

// ── Service 装配：13 个 service + 2 builder + 协议适配器 wiring 全部抽到 composeServices.ts ──
const composed = composeServices({ loadGraph, cacheCase, agentRuntimeStatus });
const {
  agentRuntimeService,
  queryRunApiService,
  evidenceOpenService,
  agentToolRegistryService,
  statisticsQueryService,
  protocolEventQueryService,
  queryRunService,
  toolRunService,
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
} = composed;

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
    insights: [],
    insightCoverage: undefined,
    path: {
      nodes: graph.path.nodes.map((node) => ({ ...node, status: "unknown" as const })),
      edges: []
    }
  };
}

// 抓包文件入库的共享逻辑：裁剪 payload → 读时间范围 → 重置分析 → 生成证据卡。
// attachments（multer 上传）与 attachments-by-path（桌面双击本地文件）共用。
async function ingestCaptureFiles(caseId: string, entries: Array<{ pcapPath: string; originalName: string }>) {
  let graph = loadGraph(caseId);
  const baseNodeIndex = graph.captures.length;
  const addedCaptures = [];
  for (const [index, entry] of entries.entries()) {
    const strippedPath = await stripPayload(entry.pcapPath);
    const pcapFilename = path.basename(strippedPath);
    const capture = CaptureNodeSchema.parse({
      nodeId: `node-${baseNodeIndex + index + 1}`,
      name: entry.originalName.replace(/\.[^.]+$/, "") || `抓包节点 ${baseNodeIndex + index + 1}`,
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
  cacheCase(caseId, graph);
  return { graph, evidenceCards };
}

function captureUploadResponse(graph: CaseGraph, evidenceCards: EvidenceCard[], fileCount: number) {
  return {
    graph,
    evidenceCards,
    agentAnswer: {
      answer: [
        `已收到 ${fileCount} 个数据包文件。`,
        ...evidenceCards.map((card) => `- ${card.summary}`),
        "请补充这些抓包节点的角色、抓包位置、入/出方向，以及故障时间、源地址、目的地址和端口。"
      ].join("\n"),
      thoughts: ["接收 pcap。", "裁剪 payload 后用 tshark-query 读取时间范围。", "当前缺少节点上下文，先追问必要信息。"],
      evidenceCards,
      actions: ["request_upload"],
      missingContext: ["节点角色", "抓包位置", "入/出方向", "故障时间", "源地址", "目的地址", "端口"],
      confidence: "needs_context"
    }
  };
}

async function loadGraphWithInsights(caseId: string): Promise<CaseGraph> {
  const graph = loadGraph(caseId);
  if (graph.insights?.length) return graph;

  // 如果 graph 没有 packets 但有 captures，先跑多协议异常预提取
  if (!graph.packets.length && graph.captures.length) {
    try {
      const inputs = captureQueryInputs(graph);
      if (inputs.length) {
        const extraction = await extractProtocolAnomalies(inputs, graph.mappingHints);
        if (extraction.packets.length) {
          const insightCoverage = {
            extractedPacketCount: extraction.packets.length,
            truncated: extraction.truncated,
            note: extraction.note
          };
          const enriched = { ...graph, packets: extraction.packets, insightCoverage };
          writeCaseGraph(enriched);
          cacheCase(caseId, enriched);
          const insights = runLevel1Insights(enriched);
          if (insights.length) {
            const nextGraph = { ...enriched, insights };
            writeCaseGraph(nextGraph);
            cacheCase(caseId, nextGraph);
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
      cacheCase(caseId, nextGraph);
      return nextGraph;
    }
  }
  return graph;
}

export const pathCorrelationTestHooks = {
  buildQueryPath
};

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
    // resource_not_found 常见原因：baseURL 缺 /v1 后缀，或模型名写错
    if (response.status === 404 || body.includes("resource_not_found") || body.includes("not found")) {
      const hint = !input.baseURL.includes("/v1") && !input.baseURL.includes("/v2") && !input.baseURL.includes("/paas")
        ? `\n\n提示：baseURL 通常需要以 /v1 结尾（如 https://api.moonshot.cn/v1），当前填的是 ${input.baseURL}`
        : `\n\n提示：模型名「${input.model}」可能不正确，请到供应商文档确认可用模型名。`;
      return { ok: false, status: response.status, error: (body.slice(0, 300) || response.statusText) + hint };
    }
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

  // MCP Server 清单（静态元数据，仅展示用途、工具数和运行方式，不含启停/状态）
  // MCP server 状态（注册制）
  router.get("/settings/mcp", async (_req, res) => {
    try {
      const statuses = await listMcpStatus();
      // 补充 case-graph（进程内调用，不在注册表里）
      res.json({
        servers: [
          ...statuses.map((s) => ({
            id: s.id,
            name: s.name,
            description: s.type === "local" ? "本地 stdio" : s.type === "sse" ? "远程 SSE" : "远程 HTTP",
            toolCount: s.toolCount,
            toolNames: s.toolNames,
            kind: s.type,
            enabled: s.enabled,
            builtIn: s.builtIn,
            connected: s.connected,
            error: s.error,
            type: s.type
          })),
          {
            id: "case-graph",
            name: "case-graph-mcp",
            description: "Agent 读写 case graph（进程内调用，22 个工具）",
            toolCount: 22,
            kind: "进程内调用",
            enabled: true,
            builtIn: true,
            connected: true,
            type: "in-process"
          }
        ]
      });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // MCP server 注册表 CRUD
  router.get("/mcp-servers", (_req, res) => {
    res.json({ servers: loadMcpServers() });
  });

  router.post("/mcp-servers", (req, res) => {
    try {
      const config = req.body as McpServerConfig;
      if (!config?.id || !config?.name || !config?.type) {
        return res.status(400).json({ error: "缺少必填字段：id/name/type" });
      }
      const servers = upsertServer(config);
      res.json({ servers });
    } catch (error) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/mcp-servers/:id/toggle", (req, res) => {
    const updated = toggleServer(String(req.params.id));
    if (!updated) return res.status(404).json({ error: "server not found" });
    res.json({ server: updated });
  });

  router.delete("/mcp-servers/:id", (req, res) => {
    const result = removeServer(String(req.params.id));
    if (!result.removed) return res.status(400).json({ error: result.reason });
    res.json({ removed: true });
  });

  // Skills 目录列表 + 新增
  router.get("/skills-dirs", (_req, res) => {
    res.json({
      main: apiConfig.skills.dir,
      extra: apiConfig.skills.extraDirs
    });
  });

  router.post("/skills-dirs", (req, res) => {
    const dir = typeof req.body?.dir === "string" ? req.body.dir.trim() : "";
    if (!dir) return res.status(400).json({ error: "缺少 dir" });
    if (!apiConfig.skills.extraDirs.includes(dir)) {
      apiConfig.skills.extraDirs.push(dir);
    }
    res.json({ main: apiConfig.skills.dir, extra: apiConfig.skills.extraDirs });
  });

  router.delete("/skills-dirs", (req, res) => {
    const dir = typeof req.query.dir === "string" ? req.query.dir : "";
    apiConfig.skills.extraDirs = apiConfig.skills.extraDirs.filter((d) => d !== dir);
    res.json({ main: apiConfig.skills.dir, extra: apiConfig.skills.extraDirs });
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

  // RFC 知识库：只读检索与状态查询（调试/前端用；Agent 走进程内工具）
  router.get("/rag/search", (req, res) => {
    const query = String(req.query.q || "").trim();
    if (!query) return res.status(400).json({ error: "q 参数不能为空" });
    const topK = Number(req.query.topK) || undefined;
    try {
      return res.json({ hits: searchRfc(query, topK) });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/rag/status", (_req, res) => {
    try {
      return res.json(rfcIndexStatus());
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // 阶段 3a：完整 RFC 库静默下载（双层库上层）
  router.get("/rag/download/status", (_req, res) => {
    return res.json(getDownloadStatus());
  });

  router.post("/rag/download/start", async (_req, res) => {
    try {
      const status = await startDownload();
      return res.json(status);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/rag/download/cancel", (_req, res) => {
    return res.json(cancelDownload());
  });

  router.delete("/rag/download", (_req, res) => {
    return res.json(deleteDownloadedDb());
  });

  // 实战知识库：列表/详情 + 沉淀闭环（verify/dispute/create）
  router.get("/field-notes", (_req, res) => {
    try {
      return res.json({ notes: listAllFieldNotes(), status: fieldNotesIndexStatus() });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/field-notes/status", (_req, res) => {
    try {
      return res.json(fieldNotesIndexStatus());
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/field-notes/:id", (req, res) => {
    const note = getFieldNote(String(req.params.id));
    if (!note) return res.status(404).json({ error: "field note not found" });
    return res.json(note);
  });

  router.post("/field-notes/:id/verify", (req, res) => {
    const result = verifyFieldNote(String(req.params.id));
    if (!result.updated) return res.status(404).json({ error: "field note not found" });
    return res.json(result.note);
  });

  router.post("/field-notes/:id/dispute", (req, res) => {
    const correction = typeof req.body?.correction === "string" ? req.body.correction : undefined;
    const result = disputeFieldNote(String(req.params.id), correction);
    if (!result.updated) return res.status(404).json({ error: "field note not found" });
    return res.json(result.note);
  });

  const CreateFieldNoteSchema = z.object({
    id: z.string().min(1),
    title: z.string().min(1),
    summary: z.string().min(1),
    protocols: z.array(z.string()).default([]),
    symptoms: z.array(z.string()).default([]),
    packetFeatures: z.object({
      observedFlags: z.array(z.string()).optional(),
      missingFlags: z.array(z.string()).optional(),
      analysisFlags: z.array(z.string()).optional(),
      protocols: z.array(z.string()).optional()
    }),
    candidateCauses: z.array(z.object({
      cause: z.string(),
      rfcDocId: z.number().int().optional(),
      rfcSection: z.string().optional(),
      likelihood: z.enum(["high", "medium", "low"]),
      howToVerify: z.string(),
      skillIds: z.array(z.string()).optional()
    })),
    source: z.string().default("user")
  });

  router.post("/field-notes", (req, res) => {
    const parsed = CreateFieldNoteSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      const result = createFieldNote(parsed.data);
      if (!result.created) return res.status(409).json({ error: result.reason });
      return res.status(201).json(result.note);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.delete("/field-notes/:id", (req, res) => {
    try {
      deleteFieldNote(String(req.params.id));
      return res.json({ deleted: true });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // Skills：列表/详情/创建/删除
  router.get("/skills", (_req, res) => {
    try {
      return res.json({ skills: listSkillsWithStatus(), status: skillsIndexStatus() });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/skills/:name/toggle", (req, res) => {
    try {
      const enabled = toggleSkill(String(req.params.name));
      return res.json({ name: req.params.name, enabled });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/skills/:name", (req, res) => {
    const skill = getSkill(String(req.params.name));
    if (!skill) return res.status(404).json({ error: "skill not found" });
    return res.json(skill);
  });

  const CreateSkillSchema = z.object({
    name: z.string().min(1),
    description: z.string().min(1),
    triggers: z.array(z.string()).optional(),
    toolsRequired: z.array(z.string()).optional(),
    body: z.string().min(1),
    overwrite: z.boolean().optional()
  });

  router.post("/skills", (req, res) => {
    const parsed = CreateSkillSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    const result = createSkill(parsed.data);
    if (!result.created) return res.status(409).json({ error: result.reason });
    return res.status(201).json({ name: parsed.data.name, filePath: result.filePath });
  });

  router.delete("/skills/:name", (req, res) => {
    const result = deleteSkill(String(req.params.name));
    return res.json(result);
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
    cacheCase(caseId, graph);
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
      cacheCase(nextGraph.spec.caseId, nextGraph);
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
    cacheCase(caseId, graph);
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
      cacheCase(caseId, graph);
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
      const { graph, evidenceCards } = await ingestCaptureFiles(caseId, files.map((file) => ({ pcapPath: file.path, originalName: file.originalname })));
      return res.status(201).json(captureUploadResponse(graph, evidenceCards, files.length));
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // 桌面端双击 .pcap：按本地路径入库（先 copy 进 captures 目录，绝不改动用户原文件）
  router.post(`/cases/:caseId/attachments-by-path`, async (req, res) => {
    const caseId = String(req.params.caseId);
    const rawPaths = Array.isArray(req.body?.paths) ? req.body.paths : [];
    const sourcePaths = rawPaths.filter((item: unknown): item is string => typeof item === "string" && /\.(pcap|pcapng|cap)$/i.test(item));
    if (!sourcePaths.length) return res.status(400).json({ error: "paths must be a non-empty array of .pcap/.pcapng/.cap file paths" });
    try {
      const directory = capturesDirectory(caseId);
      mkdirSync(directory, { recursive: true });
      const entries = sourcePaths.map((sourcePath: string, index: number) => {
        if (!existsSync(sourcePath)) throw new Error(`file not found: ${sourcePath}`);
        const originalName = path.basename(sourcePath);
        const destPath = path.join(directory, `${Date.now()}-${index}-${safePathPart(originalName)}`);
        copyFileSync(sourcePath, destPath);
        return { pcapPath: destPath, originalName };
      });
      const { graph, evidenceCards } = await ingestCaptureFiles(caseId, entries);
      return res.status(201).json(captureUploadResponse(graph, evidenceCards, entries.length));
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
      cacheCase(graph.spec.caseId, nextGraph);
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
      cacheCase(graph.spec.caseId, nextGraph);
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

  // 飞轮反馈（阶段 2d）：用户确认/纠正当前诊断 → 沉淀/标记实战笔记
  // verify：把当前 case 的根因 + packetFeatures 沉淀为新 field-note
  // dispute：标记某条根因为错误（可选 correction 文本），若有 noteId 则 dispute 该笔记
  router.post("/cases/:caseId/flywheel", (req, res) => {
    const caseId = String(req.params.caseId);
    const action = req.body?.action as "verify" | "dispute" | undefined;
    if (action !== "verify" && action !== "dispute") {
      return res.status(400).json({ error: "action 必须是 verify 或 dispute" });
    }
    try {
      const graph = loadGraph(caseId);
      const rootCauses = Array.isArray(req.body?.rootCauses) ? req.body.rootCauses : [];
      const noteId = typeof req.body?.noteId === "string" ? req.body.noteId : undefined;
      const correction = typeof req.body?.correction === "string" ? req.body.correction.trim() : "";

      if (action === "dispute" && noteId) {
        // dispute 已有笔记
        const result = disputeFieldNote(noteId, correction || undefined);
        if (!result.updated) return res.status(404).json({ error: "field note not found" });
        return res.json({ action: "dispute", note: result.note });
      }

      // verify（或 dispute 无 noteId）：用当前 case graph + rootCauses 创建新笔记
      const packetFeatures = extractPacketFeatures(graph);
      const protocols = Array.from(new Set([
        ...(packetFeatures.protocols || []),
        ...rootCauses.flatMap((c: { evidenceCardIds?: string[] }) => [])
      ])).filter(Boolean) as string[];
      const candidateCauses = rootCauses.map((cause: {
        id: string; description: string; rfcVerified?: boolean; rfcSection?: string; confidence?: string;
      }) => ({
        cause: cause.description,
        rfcSection: cause.rfcSection,
        likelihood: cause.confidence === "certain" || cause.confidence === "high" ? "high" as const
          : cause.confidence === "low" ? "low" as const : "medium" as const,
        howToVerify: cause.rfcVerified ? "已用 RFC 章节验证" : "建议补充抓包或 RFC 引用核实",
      }));
      const stamp = new Date().toISOString().replace(/[-:.]/g, "").slice(0, 14);
      const noteInput = {
        id: `fn-flywheel-${caseId.slice(-12)}-${stamp}`,
        title: rootCauses[0]?.description?.slice(0, 60) || `诊断反馈 ${stamp}`,
        summary: rootCauses.map((c: { description: string; rfcVerified?: boolean }) =>
          `${c.rfcVerified ? "[验证]" : "[推测]"} ${c.description}`
        ).join("\n") + (action === "dispute" && correction ? `\n[用户纠正] ${correction}` : ""),
        protocols,
        symptoms: [],
        packetFeatures,
        candidateCauses,
        source: action === "verify" ? "flywheel-verify" : "flywheel-dispute",
      };
      const result = createFieldNote(noteInput);
      if (!result.created) {
        // 笔记已存在（同 case 同时间戳重复反馈）→ verify 则 +1，dispute 则 +1
        if (result.note) {
          const updated = action === "verify"
            ? verifyFieldNote(result.note.id)
            : disputeFieldNote(result.note.id, correction || undefined);
          return res.json({ action, note: updated.note, deduplicated: true });
        }
        return res.status(409).json({ error: result.reason });
      }
      // verify 新笔记时也记一次 verified
      if (action === "verify" && result.note) {
        verifyFieldNote(result.note.id);
      }
      return res.status(201).json({ action, note: getFieldNote(noteInput.id) });
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // 知识脉络（阶段 3）：返回当前 case 的三层知识体系快照 —— 实战库命中 + Skills + RFC 引用
  // 供右栏知识脉络 Tab 展示 Agent 排障时调用的知识层。
  router.get("/cases/:caseId/knowledge", (req, res) => {
    try {
      const graph = loadGraph(String(req.params.caseId));
      // 1. 实战库命中：用当前 case 的 packetFeatures 检索
      let fieldNoteHits: Array<{ id: string; title: string; summary: string; featureScore: number; verifiedCount: number; disputedCount: number }> = [];
      try {
        const features = extractPacketFeatures(graph);
        const hits = searchFieldNotes(features, apiConfig.fieldNotes.topK);
        fieldNoteHits = hits.map((h) => ({
          id: h.note.id,
          title: h.note.title,
          summary: h.note.summary,
          featureScore: h.featureScore,
          verifiedCount: h.note.verifiedCount,
          disputedCount: h.note.disputedCount
        }));
      } catch {
        // 知识库未构建时降级为空数组
      }
      // 2. RFC 引用：从 activeQueryRun 的 rootCauses（如果有）+ candidateCauses 提取
      const activeQueryRun = graph.queryRuns?.find((r) => r.queryRunId === graph.activeQueryRunId) || graph.queryRuns?.[0];
      const rfcRefs: Array<{ docId?: number; section?: string; title?: string }> = [];
      // 从 toolRuns 里提取 Agent 调用过的 RFC（get_rfc_section 留下的痕迹）
      for (const run of graph.toolRuns || []) {
        const rfcMatch = run.summary?.match(/RFC\s*(\d+)/i);
        if (rfcMatch) {
          rfcRefs.push({ docId: Number(rfcMatch[1]), title: run.summary.slice(0, 80) });
        }
      }
      return res.json({
        fieldNoteHits,
        skills: listSkills().map((s) => ({ name: s.name, description: s.description })),
        rfcRefs: rfcRefs.slice(0, 6),
        rfcTier: (() => {
          try { return rfcIndexStatus().tier; } catch { return "none"; }
        })()
      });
    } catch {
      return res.status(404).json({ error: "case not found" });
    }
  });

  router.post("/cases/:caseId/agent", async (req, res) => {
    const caseId = String(req.params.caseId);
    const parsedRequest = AgentRequestSchema.safeParse(req.body || {});
    if (!parsedRequest.success) return res.status(400).json({ error: parsedRequest.error.flatten() });
    const requestedProfileId = parsedRequest.data.profileId;
    if (requestedProfileId && !activateLlmProfile(requestedProfileId)) {
      return res.status(404).json({ error: "llm profile not found" });
    }

    try {
      // 整个 agent 运行周期包在 per-case 锁内：loadGraphWithInsights → run → syncMemory 全程串行，
      // 避免并发 agent run 互相覆盖 QueryRun 和 insights
      const result = await withCaseRunLock(caseId, async () => {
        const graph = await loadGraphWithInsights(caseId);
        return agentRuntimeService.run(graph, parsedRequest.data);
      });
      return res.json(result.answer);
    } catch (error) {
      // loadGraphWithInsights 内部 loadGraph→readCaseGraph 在 case 不存在时抛 ENOENT 等，映射 404；
      // 其余为 agent 运行错误，映射 502
      const message = error instanceof Error ? error.message : String(error);
      const isMissing = message.includes("ENOENT") || message.includes("not found") || message.includes("no such file");
      return res.status(isMissing ? 404 : 502).json({ error: message });
    }
  });

  router.post("/cases/:caseId/agent/stream", async (req, res) => {
    const caseId = String(req.params.caseId);
    const parsedRequest = AgentRequestSchema.safeParse(req.body || {});
    if (!parsedRequest.success) return res.status(400).json({ error: parsedRequest.error.flatten() });
    const requestedProfileId = parsedRequest.data.profileId;
    if (requestedProfileId && !activateLlmProfile(requestedProfileId)) {
      return res.status(404).json({ error: "llm profile not found" });
    }
    // 进锁 + 写 SSE headers 前先做轻量 case 存在性检查，保持与非 stream /agent 路由一致的 404 语义；
    // 否则 case 不存在时会先 flush 200 + SSE headers，错误只能以 SSE error 事件返回，外部 API 无法靠状态码判断。
    if (!existsSync(caseDirectory(caseId))) {
      return res.status(404).json({ error: "case not found" });
    }

    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    // 流式同样用 per-case 锁包裹整个运行周期；锁在 stream 结束后释放，
    // 期间并发的同 case agent run 会排队等待
    await withCaseRunLock(caseId, async () => {
      try {
        const graph = await loadGraphWithInsights(caseId);
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
    });
    return res.end();
  });

  return router;
}
