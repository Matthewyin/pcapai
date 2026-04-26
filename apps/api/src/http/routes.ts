import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { Router } from "express";
import multer from "multer";
import { z } from "zod";
import {
  AnalysisFilterSchema,
  CaptureNodeSchema,
  CaseSpecSchema,
  MappingHintSchema,
  PacketSummarySchema,
  TimeOffsetHintSchema,
  type AgentAnswer,
  type AnalysisRun,
  type CaseGraph,
  type EvidenceEvent,
  type Finding,
  type PacketSummary
} from "../../../../packages/shared/src/index.js";
import { runPcapTroubleshootingAgent } from "../agents/runtime.js";
import { apiConfig } from "../config.js";
import { buildPathGraphWithMcp, matchCrossNodeSessionsWithMcp } from "../mcp/chainBuilderClient.js";
import { normalizePacketsWithMcp } from "../mcp/packetNormalizerClient.js";
import { parsePcapWithMcp } from "../mcp/packetParserClient.js";
import { stripPayload } from "./capturePreprocess.js";
import { addCapture, capturesDirectory, caseDirectory, createEmptyCase, deleteCases, listCaseSummaries, readAnalysisRunSnapshot, readCaseGraph, safePathPart, writeAnalysisRunSnapshot, writeCaseGraph } from "./caseStore.js";
import { activateLlmProfile, deleteLlmProfiles, getLlmSettings, listLlmProfiles, saveLlmProfile, saveLlmSettings } from "./llmSettings.js";

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
const AnalyzeRequestSchema = z.object({
  client: z.string().trim().optional(),
  server: z.string().trim().optional(),
  protocol: z.string().trim().optional(),
  port: z.coerce.number().int().optional()
});
const LlmSettingsRequestSchema = z.object({
  baseURL: z.string().url(),
  model: z.string().min(1),
  apiKey: z.string().optional()
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
  profileId: z.string().min(1).optional(),
  thinkingDepth: z.string().min(1).optional(),
  reasoningDepth: z.string().min(1).optional()
});
const ParsePcapRequestSchema = z.object({
  caseId: z.string().min(1),
  nodeId: z.string().min(1),
  pcapPath: z.string().min(1),
  pcapFilename: z.string().optional()
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

function matchesEndpoint(packet: PacketSummary, ip?: string) {
  return !ip || packet.srcIp === ip || packet.dstIp === ip;
}

function matchesPort(packet: PacketSummary, port?: number) {
  return !port || packet.srcPort === port || packet.dstPort === port;
}

function filterPackets(packets: PacketSummary[], filter: z.infer<typeof AnalyzeRequestSchema>) {
  return packets.filter((packet) => {
    const protocolMatched = !filter.protocol || packet.protocol === filter.protocol.toLowerCase();
    return protocolMatched && matchesEndpoint(packet, filter.client) && matchesEndpoint(packet, filter.server) && matchesPort(packet, filter.port);
  });
}

async function parseRawPackets(graph: CaseGraph) {
  const packetGroups = await Promise.all(graph.captures.map((capture) => {
    if (!capture.pcapFilename) return Promise.resolve([]);
    return parsePcapWithMcp({
      caseId: graph.spec.caseId,
      nodeId: capture.nodeId,
      pcapPath: path.join(capturesDirectory(graph.spec.caseId), capture.pcapFilename),
      pcapFilename: capture.pcapFilename
    }).then((result) => result.packets);
  }));
  return packetGroups.flat().map((packet) => PacketSummarySchema.parse(packet));
}

function resetAnalysis(graph: CaseGraph) {
  return {
    ...graph,
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    evidence: [],
    findings: [],
    path: {
      nodes: graph.path.nodes.map((node) => ({ ...node, status: "unknown" as const })),
      edges: []
    }
  };
}

function createAnalysisRun(graph: CaseGraph, kind: AnalysisRun["kind"], summary: string) {
  const runId = `run-${Date.now()}`;
  const run: AnalysisRun = {
    runId,
    createdAt: new Date().toISOString(),
    kind,
    summary,
    captureCount: graph.captures.length,
    rawPacketCount: graph.rawPackets.length,
    packetCount: graph.packets.length,
    findingCount: graph.findings.length,
    analysisFilter: graph.analysisFilter,
    snapshotFilename: `${runId}.json`
  };
  const nextGraph: CaseGraph = {
    ...graph,
    activeRunId: runId,
    analysisRuns: [run, ...(graph.analysisRuns || [])].slice(0, 30)
  };
  writeCaseGraph(nextGraph);
  writeAnalysisRunSnapshot(nextGraph, run);
  return nextGraph;
}

function nodeName(graph: CaseGraph, nodeId: string) {
  return graph.captures.find((capture) => capture.nodeId === nodeId)?.name || nodeId;
}

function linkEvidenceEvents(graph: CaseGraph, evidence: EvidenceEvent[]) {
  const linkEvidence: EvidenceEvent[] = graph.sessionLinks.map((link) => ({
    evidenceId: `link-evidence-${link.linkId}`,
    kind: "session_link",
    title: `跨节点会话关联：${nodeName(graph, link.fromNodeId)} -> ${nodeName(graph, link.toNodeId)}`,
    nodeId: link.toNodeId,
    packetIds: [
      ...(graph.sessions.find((session) => session.segmentId === link.fromSegmentId)?.packetIds || []),
      ...(graph.sessions.find((session) => session.segmentId === link.toSegmentId)?.packetIds || [])
    ],
    detail: `置信度 ${link.confidence}，分数 ${link.score}。依据：${link.matchReasons.join("；") || "无"}。反证：${link.counterEvidence.join("；") || "无"}`,
    confidence: link.confidence
  }));
  return [...linkEvidence, ...evidence];
}

function attributedFindings(graph: CaseGraph, evidence: EvidenceEvent[]): Finding[] {
  const findings: Finding[] = [];
  for (const edge of graph.path.edges) {
    const edgeLinks = graph.sessionLinks.filter((link) => link.fromNodeId === edge.fromNodeId && link.toNodeId === edge.toNodeId);
    const edgeEvidence = evidence.filter((event) => {
      if (event.kind === "session_link") return edgeLinks.some((link) => event.evidenceId === `link-evidence-${link.linkId}`);
      return event.nodeId === edge.fromNodeId || event.nodeId === edge.toNodeId;
    });
    if (edge.status === "unknown") {
      findings.push({
        findingId: `finding-${findings.length + 1}`,
        title: `待补上下文：${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}`,
        summary: "当前筛选结果无法把相邻节点的会话可靠关联起来。可能原因包括地址转换线索缺失、时间偏移未配置、抓包窗口不重叠或筛选条件过窄。",
        evidenceIds: edgeEvidence.map((event) => event.evidenceId),
        packetIds: edgeEvidence.flatMap((event) => event.packetIds),
        confidence: "needs_context",
        nextSteps: ["补充 NAT/SLB/代理/网关转换线索", "补充相邻节点时间偏移", "确认两个节点抓包时间窗口是否重叠", "放宽筛选条件后重新分析"]
      });
    } else if (edge.status === "suspect") {
      findings.push({
        findingId: `finding-${findings.length + 1}`,
        title: `低置信关联：${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}`,
        summary: "相邻节点存在候选会话关联，但证据不足以形成高置信路径。请优先核对反证和缺失上下文。",
        evidenceIds: edgeEvidence.map((event) => event.evidenceId),
        packetIds: edgeEvidence.flatMap((event) => event.packetIds),
        confidence: "low",
        nextSteps: ["检查跨节点关联表中的反证", "补充地址转换或时间偏移线索", "确认节点顺序和入/出方向"]
      });
    }
  }

  if (!findings.length && graph.sessionLinks.some((link) => link.confidence === "high")) {
    const evidenceIds = evidence.filter((event) => event.kind === "session_link").map((event) => event.evidenceId);
    findings.push({
      findingId: "finding-1",
      title: "当前路径已形成高置信关联",
      summary: "当前筛选流量在相邻节点之间均存在高置信会话关联。首版未发现明确网络断点。",
      evidenceIds,
      packetIds: evidence.filter((event) => event.kind === "session_link").flatMap((event) => event.packetIds),
      confidence: "high",
      nextSteps: ["如仍有访问失败，请继续检查服务端响应、应用层错误或未覆盖的抓包节点"]
    });
  }

  return findings;
}

function caseReportMarkdown(graph: CaseGraph) {
  const lines = [
    `# ${graph.spec.title}`,
    "",
    "## 案例概览",
    `- 案例 ID: ${graph.spec.caseId}`,
    `- 原始包数: ${graph.rawPackets.length}`,
    `- 当前筛选包数: ${graph.packets.length}`,
    `- 筛选条件: ${graph.analysisFilter.client || "*"} -> ${graph.analysisFilter.server || "*"}:${graph.analysisFilter.port ?? "*"} ${graph.analysisFilter.protocol || "*"}`,
    "",
    "## 抓包节点",
    ...graph.captures.map((capture) => `- ${capture.name} (${capture.nodeId}): ${capture.role}, ${capture.interfaceDirection}, ${capture.capturePosition || "-"}`),
    "",
    "## 访问路径",
    ...(graph.path.edges.length ? graph.path.edges.map((edge) => `- ${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}: ${edge.label} (${edge.status})`) : ["- 尚未生成路径边"]),
    "",
    "## 跨节点关联",
    ...(graph.sessionLinks.length ? graph.sessionLinks.map((link) => `- ${link.linkId}: ${nodeName(graph, link.fromNodeId)} -> ${nodeName(graph, link.toNodeId)}, ${link.confidence}, score=${link.score}; 依据: ${link.matchReasons.join("；") || "-"}; 反证: ${link.counterEvidence.join("；") || "-"}`) : ["- 尚未生成跨节点关联"]),
    "",
    "## 判断结果",
    ...(graph.findings.length ? graph.findings.flatMap((finding) => [
      `- ${finding.title} (${finding.confidence})`,
      `  - ${finding.summary}`,
      `  - 证据: ${finding.evidenceIds.join(", ") || "-"}`,
      `  - 下一步: ${finding.nextSteps.join("；") || "-"}`
    ]) : ["- 尚未生成判断结果"]),
    "",
    "## 关键证据",
    ...(graph.evidence.length ? graph.evidence.map((event) => `- ${event.evidenceId}: ${event.title}; ${event.detail}; packets=${event.packetIds.join(",") || "-"}`) : ["- 尚未生成证据"])
  ];
  return lines.join("\n");
}

function fallbackAgentAnswer(graph: CaseGraph): AgentAnswer {
  return {
    answer: graph.findings[0]
      ? `${graph.findings[0].title}: ${graph.findings[0].summary}`
      : "当前 case graph 还没有 finding。请先完成 pcap 解析和后续会话归一化/诊断步骤。",
    evidenceIds: graph.findings[0]?.evidenceIds || [],
    packetIds: graph.findings[0]?.packetIds || [],
    sessionLinkIds: [],
    findingIds: graph.findings[0] ? [graph.findings[0].findingId] : [],
    missingContext: [],
    confidence: graph.findings[0]?.confidence,
    suggestedActions: graph.findings[0]?.nextSteps || [],
    handoffAgent: "fallback"
  };
}

function buildAgentQuestion(input: z.infer<typeof AgentRequestSchema>) {
  const depthInstruction = [
    input.thinkingDepth ? `思考深度：${input.thinkingDepth}` : "",
    input.reasoningDepth ? `推理深度：${input.reasoningDepth}` : ""
  ].filter(Boolean).join("；");
  return depthInstruction ? `${input.question}\n\n本次回答控制：${depthInstruction}` : input.question;
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
      stream: false
    })
  });
  if (!response.ok) {
    const body = await response.text();
    return { ok: false, status: response.status, error: body.slice(0, 500) || response.statusText };
  }
  return { ok: true, status: response.status };
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
    return res.json({ ...saveLlmSettings(parsed.data), profiles: listLlmProfiles() });
  });

  router.get("/settings/llm/profiles", (_req, res) => {
    res.json({ profiles: listLlmProfiles(), settings: getLlmSettings() });
  });

  router.post("/settings/llm/profiles", (req, res) => {
    const parsed = LlmProfileRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    return res.json({ ...saveLlmProfile(parsed.data), profiles: listLlmProfiles() });
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

  router.post(`/cases/:caseId/captures`, upload.array(apiConfig.uploadFieldName), async (req, res) => {
    const caseId = String(req.params.caseId);
    const files = Array.isArray(req.files) ? req.files : [];
    if (!files.length) return res.status(400).json({ error: `${apiConfig.uploadFieldName} file is required` });
    const metadata = parseCaptureMetadata(req.body.metadata) || fallbackCaptureMetadata(req.body, files);
    if (!metadata?.success) return res.status(400).json({ error: "capture metadata is required" });

    try {
      let graph = loadGraph(caseId);
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
      }
      graph = resetAnalysis(graph);
      graph = createAnalysisRun(graph, "capture_update", `追加或替换 ${files.length} 个抓包文件，已重置分析结果。`);
      cases.set(caseId, graph);
      return res.status(201).json(graph);
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
    } catch {
      return res.status(404).json({ error: "case not found" });
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
    } catch {
      return res.status(404).json({ error: "case not found" });
    }
  });

  router.post("/cases/:caseId/parse", async (req, res) => {
    const caseId = String(req.params.caseId);
    try {
      const graph = loadGraph(caseId);
      const rawPackets = await parseRawPackets(graph);
      const nextGraph: CaseGraph = {
        ...graph,
        rawPackets,
        packets: [],
        sessions: [],
        sessionLinks: [],
        evidence: [],
        findings: [],
        path: {
          nodes: graph.path.nodes.map((node) => ({ ...node, status: "unknown" as const })),
          edges: []
        }
      };
      const outputDirectory = caseDirectory(graph.spec.caseId);
      mkdirSync(outputDirectory, { recursive: true });
      writeFileSync(path.join(outputDirectory, "raw-packets.json"), JSON.stringify(rawPackets, null, 2));
      const graphWithRun = createAnalysisRun(nextGraph, "parse", `解析 ${nextGraph.captures.length} 个抓包节点，读取 ${rawPackets.length} 个原始包摘要。`);
      cases.set(graph.spec.caseId, graphWithRun);
      return res.json(graphWithRun);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/cases/:caseId/analyze", async (req, res) => {
    const caseId = String(req.params.caseId);
    const parsed = AnalyzeRequestSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    try {
      const graph = loadGraph(caseId);
      const rawPackets = graph.rawPackets.length ? graph.rawPackets : await parseRawPackets(graph);
      const analysisFilter = AnalysisFilterSchema.parse(parsed.data);
      const packets = filterPackets(rawPackets, analysisFilter);
      const graphWithPackets: CaseGraph = { ...graph, rawPackets, analysisFilter, packets };
      const normalized = await normalizePacketsWithMcp(graphWithPackets);
      const graphWithNormalized: CaseGraph = {
        ...graphWithPackets,
        sessions: normalized.sessions,
        evidence: normalized.evidence,
        findings: normalized.findings,
        path: normalized.path
      };
      const matched = await matchCrossNodeSessionsWithMcp(graphWithNormalized);
      const linkedPath = await buildPathGraphWithMcp(graphWithNormalized, matched.links);
      const graphWithLinks: CaseGraph = {
        ...graphWithNormalized,
        sessionLinks: matched.links,
        sessions: normalized.sessions,
        path: linkedPath,
        evidence: []
      };
      const evidence = linkEvidenceEvents(graphWithLinks, normalized.evidence);
      const nextGraph: CaseGraph = {
        ...graphWithLinks,
        evidence,
        findings: attributedFindings({ ...graphWithLinks, evidence }, evidence)
      };
      const outputDirectory = caseDirectory(graph.spec.caseId);
      mkdirSync(outputDirectory, { recursive: true });
      writeFileSync(path.join(outputDirectory, "raw-packets.json"), JSON.stringify(rawPackets, null, 2));
      writeFileSync(path.join(outputDirectory, "packets.json"), JSON.stringify(packets, null, 2));
      writeFileSync(path.join(outputDirectory, "sessions.json"), JSON.stringify(normalized.sessions, null, 2));
      writeFileSync(path.join(outputDirectory, "session-links.json"), JSON.stringify(matched.links, null, 2));
      const graphWithRun = createAnalysisRun(nextGraph, "analysis", `按当前筛选条件分析，命中 ${packets.length} 个包，生成 ${nextGraph.findings.length} 个判断。`);
      cases.set(graph.spec.caseId, graphWithRun);
      return res.json(graphWithRun);
    } catch (error) {
      return res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.post("/tools/parse-pcap", async (req, res) => {
    const parsed = ParsePcapRequestSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

    try {
      const result = await parsePcapWithMcp(parsed.data);
      const outputDirectory = caseDirectory(parsed.data.caseId);
      mkdirSync(outputDirectory, { recursive: true });
      writeFileSync(path.join(outputDirectory, "packets.json"), JSON.stringify(result.packets, null, 2));
      return res.json(result);
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
      return res.json({ markdown: caseReportMarkdown(graph) });
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

    const question = buildAgentQuestion(parsedRequest.data);
    writeStreamEvent(res, "thought", { text: "读取当前 case graph 和分析版本。" });
    writeStreamEvent(res, "thought", { text: "通过 case-graph MCP 准备证据、会话、路径和 finding 上下文。" });
    writeStreamEvent(res, "thought", { text: `使用模型 ${apiConfig.llm.model}，按本次深度参数生成解释。` });

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
      const answer = await runPcapTroubleshootingAgent({ graph, question });
      Object.assign(agentRuntimeStatus, {
        lastRunAt: new Date().toISOString(),
        lastStatus: "success",
        lastError: "",
        lastCaseId: graph.spec.caseId,
        lastModel: apiConfig.llm.model,
        lastBaseURL: apiConfig.llm.baseURL
      });
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
