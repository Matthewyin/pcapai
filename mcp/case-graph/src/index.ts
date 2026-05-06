import { readFileSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type CaseGraph = {
  spec: { caseId: string; title: string };
  captures: Array<{ nodeId: string; name: string; role: string; interfaceDirection: string; capturePosition: string }>;
  mappingHints: unknown[];
  timeOffsetHints: unknown[];
  rawPackets: Array<{ packetId: string; timestamp?: number }>;
  analysisFilter: Record<string, unknown>;
  packets: Array<{ packetId: string; timestamp?: number; srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number; protocol?: string }>;
  sessions: Array<{ segmentId: string; protocol?: string; clientIp?: string; clientPort?: number; serverIp?: string; serverPort?: number }>;
  sessionLinks: Array<{ linkId: string; fromNodeId: string; toNodeId: string; fromSegmentId: string; toSegmentId: string; confidence: string; score: number }>;
  diagnosticTags: Array<{ tagId: string; kind: string; nodeIds: string[]; segmentIds: string[]; packetIds: string[]; evidenceIds: string[]; confidence: string; summary: string; nextSteps: string[] }>;
  evidence: Array<{ evidenceId: string; kind: string; title: string; nodeId?: string; packetIds: string[]; confidence?: string }>;
  findings: Array<{ findingId: string; title: string; summary: string; confidence: string; evidenceIds: string[]; packetIds?: string[]; nextSteps: string[] }>;
  path: { edges: Array<{ fromNodeId: string; toNodeId: string; label: string; status: string }> };
  queryRuns?: Array<{
    queryRunId: string;
    question: string;
    displayFilter: string;
    totalConversationCount?: number;
    candidateGroups?: Array<{ groupId: string; protocol: string; srcIp?: string; dstIp?: string; dstPort?: number; conversationIds: string[]; selectedConversationId?: string; conversationCount: number; successCount: number; failureCount: number; rstCount: number; retransmissionCount: number; zeroWindowCount: number; failureModes?: Array<{ kind: string; label: string; count: number; conversationIds: string[] }>; firstSeen?: number; lastSeen?: number; rankScore: number; rankReasons: string[]; summary: string }>;
    selectedCandidateGroupId?: string;
    conversationIds: string[];
    selectedConversationId?: string;
    conversations: Array<{ conversationId: string; nodeId: string; pcapFilename: string; protocol: string; srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number; startTime: number; endTime: number; packetCount: number; byteCount: number; tcpFlags: string[]; rstCount: number; retransmissionCount: number; zeroWindowCount: number; rankScore?: number; rankReasons?: string[]; displayFilter: string }>;
    evidenceCards?: Array<{ cardId: string; kind: string; title: string; summary: string; pcapFilename?: string; frameNumber?: number; displayFilter?: string; packetDisplayFilter?: string; conversationId?: string; queryRunId?: string; actions: string[] }>;
    protocolCorrelations?: Array<{ correlationId: string; kind: string; sourcePacketId: string; sourceEvidenceCardId?: string; targetConversationId?: string; targetDisplayFilter: string; relation: string; confidence: string; summary: string; reasons: string[]; nextSteps: string[] }>;
    path?: {
      summary: string;
      confidence: string;
      hops: Array<{ hopId: string; nodeId: string; conversationId: string; observedTuple: string; status: string; packetCount: number; anomalies: string[]; wiresharkFilter: string; correlation?: string; correlationReasons?: string[] }>;
      edges: Array<{ edgeId: string; fromNodeId: string; toNodeId: string; status: string; label: string; diagnosis?: string; reasons?: string[]; nextSteps?: string[]; timeDeltaSeconds?: number }>;
    };
    selectedDiagnosis?: {
      conversationId: string;
      summary: string;
      confidence: string;
      checks: Array<{ key: string; label: string; status: string; summary: string; packetIds: string[]; nextSteps: string[] }>;
      diagnosticTags: Array<{ tagId: string; kind: string; nodeIds: string[]; packetIds: string[]; evidenceIds: string[]; confidence: string; summary: string; nextSteps: string[] }>;
      evidence: Array<{ evidenceId: string; kind: string; title: string; nodeId?: string; packetIds: string[]; detail: string; confidence: string }>;
      findings: Array<{ findingId: string; title: string; summary: string; tagIds: string[]; evidenceIds: string[]; packetIds: string[]; confidence: string; nextSteps: string[] }>;
      nextSteps: string[];
    };
    createdAt: string;
  }>;
  activeQueryRunId?: string;
  networkTopology?: {
    devices: Array<{ deviceId: string; name: string; type: string; description?: string; configurations?: string[] }>;
    dataPath?: Array<{ hopIndex: number; deviceName?: string; clientSideCapture?: string; serverSideCapture?: string; description?: string }>;
    notes?: string;
  };
  insights?: Array<{
    insightId: string;
    type: string;
    severity: string;
    packetIds: string[];
    description: string;
    detail: Record<string, unknown>;
    scenario?: string;
  }>;
};

const server = new McpServer({ name: "case-graph-mcp", version: "0.1.0" });

function loadGraph(): CaseGraph {
  const graphPath = process.env.PCAPAI_CASE_GRAPH_PATH;
  if (!graphPath) throw new Error("PCAPAI_CASE_GRAPH_PATH is required");
  return JSON.parse(readFileSync(graphPath, "utf8")) as CaseGraph;
}

function nodeName(graph: CaseGraph, nodeId: string) {
  return graph.captures.find((capture) => capture.nodeId === nodeId)?.name || nodeId;
}

function compactLines(lines: string[]) {
  return lines.filter((line, index, source) => line || source[index - 1]).join("\n").trimEnd();
}

function endpoint(ip?: string, port?: number) {
  return ip && port !== undefined ? `${ip}:${port}` : "";
}

function canonicalPair(first: string, second: string) {
  return first && second ? [first, second].sort().join(" <-> ") : "";
}

function tcpCommunicationStats(graph: CaseGraph) {
  const sessionPairs = new Set<string>();
  for (const session of graph.sessions) {
    if (session.protocol?.toLowerCase() !== "tcp") continue;
    const pair = canonicalPair(endpoint(session.clientIp, session.clientPort), endpoint(session.serverIp, session.serverPort));
    if (pair) sessionPairs.add(pair);
  }

  const packetPairs = new Set<string>();
  for (const packet of graph.packets) {
    if (packet.protocol?.toLowerCase() !== "tcp") continue;
    const pair = canonicalPair(endpoint(packet.srcIp, packet.srcPort), endpoint(packet.dstIp, packet.dstPort));
    if (pair) packetPairs.add(pair);
  }

  const source = sessionPairs.size ? "sessions" : "packets";
  return {
    definition: "TCP 通信对 = TCP 端点对（IP:Port <-> IP:Port）按无方向去重；优先使用 session，session 不存在时使用 packet。",
    source,
    tcpSessionSegments: graph.sessions.filter((session) => session.protocol?.toLowerCase() === "tcp").length,
    tcpCommunicationPairs: source === "sessions" ? sessionPairs.size : packetPairs.size,
    packetDerivedPairs: packetPairs.size
  };
}

function diagnosticStats(graph: CaseGraph) {
  const diagnosticTags = graph.diagnosticTags || [];
  const byKind = diagnosticTags.reduce<Record<string, number>>((counts, tag) => {
    counts[tag.kind] = (counts[tag.kind] || 0) + 1;
    return counts;
  }, {});
  return {
    total: diagnosticTags.length,
    byKind,
    rst: byKind.rst_first_seen_at_node || 0,
    retransmission: byKind.retransmission_burst || 0,
    duplicateAck: byKind.dup_ack_burst || 0,
    zeroWindow: byKind.zero_window || 0,
    singleNodeSession: byKind.session_seen_on_one_node_only || 0
  };
}

function packetTimeRangeStats(packets: Array<{ timestamp?: number }>) {
  const timestamps = packets.map((packet) => packet.timestamp).filter((timestamp): timestamp is number => Number.isFinite(timestamp));
  if (!timestamps.length) {
    return {
      packetCount: packets.length,
      timestampCount: 0,
      startEpoch: null,
      endEpoch: null,
      startIso: null,
      endIso: null,
      durationSeconds: null
    };
  }
  const startEpoch = Math.min(...timestamps);
  const endEpoch = Math.max(...timestamps);
  return {
    packetCount: packets.length,
    timestampCount: timestamps.length,
    startEpoch,
    endEpoch,
    startIso: new Date(startEpoch * 1000).toISOString(),
    endIso: new Date(endEpoch * 1000).toISOString(),
    durationSeconds: Math.max(0, endEpoch - startEpoch)
  };
}

function caseStatistics(graph: CaseGraph) {
  const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
  return {
    tcp: tcpCommunicationStats(graph),
    diagnostics: diagnosticStats(graph),
    queryRuns: {
      total: graph.queryRuns?.length || 0,
      activeQueryRunId: graph.activeQueryRunId || null,
      activeConversationCount: activeQueryRun?.conversations.length || 0,
      activeTotalConversationCount: activeQueryRun?.totalConversationCount || activeQueryRun?.conversations.length || 0,
      activeCandidateGroupCount: activeQueryRun?.candidateGroups?.length || 0,
      selectedConversationId: activeQueryRun?.selectedConversationId || null
    },
    timeRanges: {
      allCapturedPackets: packetTimeRangeStats(graph.rawPackets || []),
      filteredPackets: packetTimeRangeStats(graph.packets || [])
    }
  };
}

function graphSummary(graph: CaseGraph) {
  const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
  return {
    spec: graph.spec,
    analysisFilter: graph.analysisFilter,
    counts: {
      captures: graph.captures.length,
      rawPackets: graph.rawPackets.length,
      packets: graph.packets.length,
      sessions: graph.sessions.length,
      sessionLinks: graph.sessionLinks.length,
      evidence: graph.evidence.length,
      findings: graph.findings.length,
      diagnosticTags: (graph.diagnosticTags || []).length,
      queryRuns: graph.queryRuns?.length || 0,
      mappingHints: graph.mappingHints.length,
      timeOffsetHints: graph.timeOffsetHints.length
    },
    statistics: caseStatistics(graph),
    captures: graph.captures.map(({ nodeId, name, role, interfaceDirection, capturePosition }) => ({
      nodeId,
      name,
      role,
      interfaceDirection,
      capturePosition
    })),
    path: graph.path,
    findings: graph.findings.map(({ findingId, title, confidence, evidenceIds, packetIds, nextSteps }) => ({
      findingId,
      title,
      confidence,
      evidenceIds,
      packetIds,
      nextSteps
    })),
    evidence: graph.evidence.map(({ evidenceId, kind, title, nodeId, packetIds, confidence }) => ({
      evidenceId,
      kind,
      title,
      nodeId,
      packetIds,
      confidence
    })),
    sessionLinks: graph.sessionLinks.map(({ linkId, fromNodeId, toNodeId, fromSegmentId, toSegmentId, confidence, score }) => ({
      linkId,
      fromNodeId,
      toNodeId,
      fromSegmentId,
      toSegmentId,
      confidence,
      score
    })),
    diagnosticTags: (graph.diagnosticTags || []).map(({ tagId, kind, nodeIds, segmentIds, evidenceIds, confidence, summary }) => ({
      tagId,
      kind,
      nodeIds,
      segmentIds,
      evidenceIds,
      confidence,
      summary
    })),
    activeQueryRun: activeQueryRun ? {
      queryRunId: activeQueryRun.queryRunId,
      question: activeQueryRun.question,
      displayFilter: activeQueryRun.displayFilter,
      totalConversationCount: activeQueryRun.totalConversationCount || activeQueryRun.conversations.length,
      candidateGroups: (activeQueryRun.candidateGroups || []).map((group) => ({
        groupId: group.groupId,
        summary: group.summary,
        conversationCount: group.conversationCount,
        successCount: group.successCount,
        failureCount: group.failureCount,
        rstCount: group.rstCount,
        retransmissionCount: group.retransmissionCount,
        zeroWindowCount: group.zeroWindowCount,
        failureModes: group.failureModes || [],
        selectedConversationId: group.selectedConversationId,
        rankReasons: group.rankReasons
      })),
      selectedCandidateGroupId: activeQueryRun.selectedCandidateGroupId,
      conversationCount: activeQueryRun.conversations.length,
      selectedConversationId: activeQueryRun.selectedConversationId,
      topConversations: activeQueryRun.conversations.slice(0, 10).map((conversation) => ({
        conversationId: conversation.conversationId,
        nodeId: conversation.nodeId,
        tuple: `${conversation.srcIp}:${conversation.srcPort} -> ${conversation.dstIp}:${conversation.dstPort}`,
        packetCount: conversation.packetCount,
        rstCount: conversation.rstCount,
        retransmissionCount: conversation.retransmissionCount,
        zeroWindowCount: conversation.zeroWindowCount,
        rankScore: conversation.rankScore || 0,
        rankReasons: conversation.rankReasons || []
      })),
      path: activeQueryRun.path,
      protocolCorrelations: activeQueryRun.protocolCorrelations || [],
      selectedDiagnosis: activeQueryRun.selectedDiagnosis || null
    } : null
  };
}

function reportMarkdown(graph: CaseGraph) {
  const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
  if (!activeQueryRun) {
    return compactLines([
      `# ${graph.spec.title}`,
      "",
      "## 1. 当前状态",
      "- 尚未创建 QueryRun。",
      "",
      "## 2. 数据来源",
      ...graph.captures.map((capture) => `- ${capture.name} (${capture.nodeId}): ${capture.role}; ${capture.interfaceDirection}; ${capture.capturePosition || "-"}`),
      "",
      "## 3. 边界说明",
      "- 报告只基于当前 case graph，不做无证据推断。"
    ]);
  }

  const selectedConversation = activeQueryRun.conversations.find((conversation) => conversation.conversationId === activeQueryRun.selectedConversationId);
  const selectedDiagnosis = activeQueryRun.selectedDiagnosis;
  const selectedEvidence = (activeQueryRun.evidenceCards || [])[0];
  const selectedGroup = (activeQueryRun.candidateGroups || []).find((group) => group.groupId === activeQueryRun.selectedCandidateGroupId)
    || (activeQueryRun.candidateGroups || []).find((group) => selectedConversation && group.conversationIds.includes(selectedConversation.conversationId));
  const checks = selectedDiagnosis?.checks || [];
  const problemChecks = checks.filter((check) => check.status === "problem");
  const warnChecks = checks.filter((check) => check.status === "warn");
  const okChecks = checks.filter((check) => check.status === "ok");
  const nextSteps = [
    ...(selectedDiagnosis?.nextSteps || []),
    ...(activeQueryRun.path?.edges.flatMap((edge) => edge.nextSteps || []) || []),
    ...(activeQueryRun.protocolCorrelations || []).flatMap((correlation) => correlation.nextSteps || [])
  ];
  const filters = [
    `- Query filter: ${activeQueryRun.displayFilter}`,
    selectedEvidence?.displayFilter ? `- 当前证据 filter: ${selectedEvidence.displayFilter}` : "",
    selectedEvidence?.packetDisplayFilter ? `- 定位帧 filter: ${selectedEvidence.packetDisplayFilter}` : "",
    selectedConversation?.displayFilter ? `- 当前 session filter: ${selectedConversation.displayFilter}` : "",
    ...(activeQueryRun.protocolCorrelations || []).map((correlation) => `- ${correlation.kind}: ${correlation.targetDisplayFilter}`),
    ...(activeQueryRun.path?.hops || []).map((hop) => `- ${nodeName(graph, hop.nodeId)} hop: ${hop.wiresharkFilter}`)
  ].filter(Boolean);

  return compactLines([
    `# ${graph.spec.title}`,
    "",
    "## 1. 问题与查询",
    `- 案例 ID: ${graph.spec.caseId}`,
    `- QueryRun: ${activeQueryRun.queryRunId}`,
    `- 用户问题: ${activeQueryRun.question || "-"}`,
    `- Query filter: ${activeQueryRun.displayFilter}`,
    `- 通讯对数量: ${activeQueryRun.totalConversationCount || activeQueryRun.conversations.length}`,
    `- 候选访问链路组: ${activeQueryRun.candidateGroups?.length || 0}`,
    "",
    "## 2. 数据来源",
    ...graph.captures.map((capture) => `- ${capture.name} (${capture.nodeId}): ${capture.role}; ${capture.interfaceDirection}; ${capture.capturePosition || "-"}`),
    "",
    "## 3. 当前证据",
    ...(selectedEvidence ? [
      `- 证据: ${selectedEvidence.title}`,
      `- 摘要: ${selectedEvidence.summary}`,
      `- 证据类型: ${selectedEvidence.kind}`,
      `- 完整过滤器: ${selectedEvidence.displayFilter || "-"}`,
      `- 定位帧: ${selectedEvidence.packetDisplayFilter || (selectedEvidence.frameNumber ? `frame.number == ${selectedEvidence.frameNumber}` : "-")}`,
      `- pcap: ${selectedEvidence.pcapFilename || "-"}`
    ] : ["- 当前 QueryRun 尚未生成证据卡。"]),
    "",
    "## 4. L7 关联",
    ...(activeQueryRun.protocolCorrelations?.length ? activeQueryRun.protocolCorrelations.map((correlation) => `- ${correlation.kind}: ${correlation.summary}; filter=${correlation.targetDisplayFilter}; reasons=${correlation.reasons.join("；") || "-"}; next=${correlation.nextSteps.join("；") || "-"}`) : ["- 当前 QueryRun 尚未生成 L7-to-TCP 关联。"]),
    "",
    "## 5. 访问对象",
    ...(selectedConversation ? [
      `- Session: ${selectedConversation.srcIp}:${selectedConversation.srcPort} -> ${selectedConversation.dstIp}:${selectedConversation.dstPort}`,
      `- 协议/节点: ${selectedConversation.protocol}; ${nodeName(graph, selectedConversation.nodeId)}`,
      `- 时间范围: ${selectedConversation.startTime} - ${selectedConversation.endTime}`,
      `- 包数/字节: ${selectedConversation.packetCount} / ${selectedConversation.byteCount}`,
      `- RST/重传/Zero Window: ${selectedConversation.rstCount} / ${selectedConversation.retransmissionCount} / ${selectedConversation.zeroWindowCount}`,
      `- Session filter: ${selectedConversation.displayFilter}`
    ] : ["- 尚未选中访问对象。"]),
    "",
    "## 6. 多节点路径",
    ...(activeQueryRun.path?.hops.length ? activeQueryRun.path.hops.map((hop) => `- ${nodeName(graph, hop.nodeId)}: ${hop.status}; ${hop.observedTuple}; correlation=${hop.correlation || "-"}; reasons=${hop.correlationReasons?.join("；") || "-"}; packets=${hop.packetCount}; filter=${hop.wiresharkFilter}`) : ["- 当前 QueryRun 尚未生成多节点路径。"]),
    "",
    "## 7. 路径边判断",
    ...(activeQueryRun.path?.edges?.length ? activeQueryRun.path.edges.map((edge) => `- ${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}: ${edge.status}; ${edge.diagnosis || edge.label}; reasons=${edge.reasons?.join("；") || "-"}; next=${edge.nextSteps?.join("；") || "-"}${edge.timeDeltaSeconds !== undefined ? `; delta=${edge.timeDeltaSeconds.toFixed(3)}s` : ""}`) : ["- 当前 QueryRun 尚未生成路径边判断。"]),
    "",
    "## 8. 确定性诊断",
    ...(selectedDiagnosis ? [
      `- 结论: ${selectedDiagnosis.summary}`,
      `- 置信度: ${selectedDiagnosis.confidence}`
    ] : ["- 尚未生成 selected diagnosis。"]),
    ...(problemChecks.length ? problemChecks.map((check) => `- 明确异常: ${check.label}; ${check.summary}; packets=${check.packetIds.join(",") || "-"}; next=${check.nextSteps.join("；") || "-"}`) : ["- 明确异常: 无"]),
    ...(warnChecks.length ? warnChecks.map((check) => `- 需要复核: ${check.label}; ${check.summary}; packets=${check.packetIds.join(",") || "-"}; next=${check.nextSteps.join("；") || "-"}`) : []),
    ...(okChecks.length ? [`- 未见异常项: ${okChecks.map((check) => check.label).join("、")}`] : []),
    "",
    "## 9. 判断结果",
    ...(selectedDiagnosis?.findings || []).map((finding) => [
      `- ${finding.title} (${finding.confidence})`,
      `  - ${finding.summary}`,
      `  - 证据: ${finding.evidenceIds.join(", ") || "-"}`,
      `  - 下一步: ${finding.nextSteps.join("；") || "-"}`
    ].join("\n")),
    ...(selectedDiagnosis?.findings.length ? [] : ["- 当前证据用于说明协议/会话表现，不直接推断设备故障。"]),
    "",
    "## 10. 候选链路上下文",
    ...(selectedGroup ? [
      `- 当前链路组: ${selectedGroup.summary}`,
      `- 成功/异常: ${selectedGroup.successCount} / ${selectedGroup.failureCount}`,
      `- 故障形态: ${selectedGroup.failureModes?.map((mode) => `${mode.label} ${mode.count}`).join("；") || "-"}`
    ] : ["- 当前 QueryRun 未生成候选链路组。"]),
    "",
    "## 11. Wireshark 过滤器",
    ...filters,
    "",
    "## 12. 下一步动作",
    ...([...new Set(nextSteps)].filter(Boolean).length ? [...new Set(nextSteps)].filter(Boolean).map((step) => `- ${step}`) : [
      "- 在 Wireshark 中打开当前证据 filter，查看定位帧前后的协议状态。",
      "- 补充抓包节点角色、抓包方向、抓包位置后再判断是否存在中间路径断点。"
    ]),
    "",
    "## 13. 边界说明",
    "- 本报告只基于当前 QueryRun、当前证据卡、选中访问对象、路径边和 checks 生成。",
    "- 未覆盖的时间窗口、未上传的节点、未提供的 NAT/F5/LB/代理映射都不会被推断成确定故障点。",
    "- Agent 负责解释证据链；包级事实来自 tshark-query / case graph。"
  ]);
}

server.registerTool(
  "load_case_graph",
  {
    title: "Load case graph",
    description: "读取当前 case graph 摘要，不返回完整 packet 列表。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(graphSummary(loadGraph())) }]
  })
);

server.registerTool(
  "get_case_statistics",
  {
    title: "Get case statistics",
    description: "读取确定性统计结果，例如 TCP 通信对数量、诊断标签统计、捕获数据包整体时间范围。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(caseStatistics(loadGraph())) }]
  })
);

server.registerTool(
  "get_query_runs",
  {
    title: "Get query runs",
    description: "读取当前案例的 QueryRun 摘要列表（不含完整 conversations 和 packets）。",
    inputSchema: {}
  },
  async () => {
    const runs = loadGraph().queryRuns || [];
    const summaries = runs.map((run) => ({
      queryRunId: run.queryRunId,
      question: run.question,
      conversationCount: run.conversations?.length || 0,
      evidenceCardCount: run.evidenceCards?.length || 0,
      protocolCorrelationCount: run.protocolCorrelations?.length || 0,
      diagnosisChecks: run.selectedDiagnosis?.checks?.map((c: { key: string; label: string; status: string; summary: string }) => ({ key: c.key, label: c.label, status: c.status, summary: c.summary }))
    }));
    return { content: [{ type: "text", text: JSON.stringify(summaries) }] };
  }
);

server.registerTool(
  "get_query_run",
  {
    title: "Get query run",
    description: "按 queryRunId 读取通讯对、路径和 Wireshark filter。",
    inputSchema: { queryRunId: z.string() }
  },
  async ({ queryRunId }) => ({
    content: [{ type: "text", text: JSON.stringify((loadGraph().queryRuns || []).find((run) => run.queryRunId === queryRunId) || null) }]
  })
);

server.registerTool(
  "get_active_query_run",
  {
    title: "Get active query run",
    description: "读取当前激活的 QueryRun。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    return { content: [{ type: "text", text: JSON.stringify((graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId) || null) }] };
  }
);

server.registerTool(
  "get_conversation",
  {
    title: "Get conversation",
    description: "在当前 QueryRun 中按 conversationId 读取通讯对。",
    inputSchema: { conversationId: z.string() }
  },
  async ({ conversationId }) => ({
    content: [{ type: "text", text: JSON.stringify((loadGraph().queryRuns || []).flatMap((run) => run.conversations).find((conversation) => conversation.conversationId === conversationId) || null) }]
  })
);

server.registerTool(
  "get_query_diagnosis",
  {
    title: "Get query diagnosis",
    description: "读取当前 QueryRun 的 selectedDiagnosis，包括 checks、findings 和 nextSteps。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
    return { content: [{ type: "text", text: JSON.stringify(activeQueryRun?.selectedDiagnosis || null) }] };
  }
);

server.registerTool(
  "get_path_diagnosis",
  {
    title: "Get path diagnosis",
    description: "读取当前 QueryRun 的 PathHop、PathEdge 和边判断。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
    return { content: [{ type: "text", text: JSON.stringify(activeQueryRun?.path || null) }] };
  }
);

server.registerTool(
  "get_protocol_correlations",
  {
    title: "Get protocol correlations",
    description: "读取当前 QueryRun 的 DNS/TLS/HTTP 到 TCP 的确定性关联。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
    return { content: [{ type: "text", text: JSON.stringify(activeQueryRun?.protocolCorrelations || []) }] };
  }
);

server.registerTool(
  "get_evidence_cards",
  {
    title: "Get evidence cards",
    description: "读取当前 QueryRun 的证据卡片。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
    return { content: [{ type: "text", text: JSON.stringify(activeQueryRun?.evidenceCards || []) }] };
  }
);

server.registerTool(
  "get_finding",
  {
    title: "Get finding",
    description: "按 findingId 读取判断结果。",
    inputSchema: { findingId: z.string() }
  },
  async ({ findingId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().findings.find((finding) => finding.findingId === findingId) || null) }]
  })
);

server.registerTool(
  "get_evidence",
  {
    title: "Get evidence",
    description: "按 evidenceId 读取证据事件。",
    inputSchema: { evidenceId: z.string() }
  },
  async ({ evidenceId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().evidence.find((event) => event.evidenceId === evidenceId) || null) }]
  })
);

server.registerTool(
  "get_session_link",
  {
    title: "Get session link",
    description: "按 sessionLinkId 读取跨节点会话关联。",
    inputSchema: { sessionLinkId: z.string() }
  },
  async ({ sessionLinkId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().sessionLinks.find((link) => link.linkId === sessionLinkId) || null) }]
  })
);

server.registerTool(
  "get_packet_detail",
  {
    title: "Get packet detail",
    description: "按 packetId 读取数据包详情。",
    inputSchema: { packetId: z.string() }
  },
  async ({ packetId }) => {
    const graph = loadGraph();
    return {
      content: [{
        type: "text",
        text: JSON.stringify(graph.packets.find((packet) => packet.packetId === packetId) || graph.rawPackets.find((packet) => packet.packetId === packetId) || null)
      }]
    };
  }
);

server.registerTool(
  "explain_path",
  {
    title: "Explain path",
    description: "读取当前 QueryRun 的通讯路径 hop。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
    return {
      content: [{ type: "text", text: JSON.stringify({ queryRun: activeQueryRun || null, path: activeQueryRun?.path || null }) }]
    };
  }
);

server.registerTool(
  "get_network_topology",
  {
    title: "Get network topology",
    description: "读取用户提供的网络拓扑和数据路径信息。包括网络设备（防火墙、LB、WAF、SSL 等）和抓包位置。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    const topology = graph.networkTopology || null;
    if (!topology) {
      return { content: [{ type: "text", text: "当前案例尚未收集网络拓扑信息。请在诊断访谈中向用户询问网络路径和抓包位置。" }] };
    }
    return { content: [{ type: "text", text: JSON.stringify(topology) }] };
  }
);

server.registerTool(
  "update_network_topology",
  {
    title: "Update network topology",
    description: "保存从用户对话中提取的网络拓扑信息。包括网络设备和数据路径。",
    inputSchema: {
      devices: z.array(z.object({
        deviceId: z.string(),
        name: z.string(),
        type: z.enum(["firewall", "switch", "load_balancer", "ssl_terminator", "waf", "router", "proxy", "cdn", "nat_gateway", "other"]),
        description: z.string().optional(),
        configurations: z.array(z.string()).optional()
      })),
      dataPath: z.array(z.object({
        hopIndex: z.number(),
        deviceName: z.string().optional(),
        clientSideCapture: z.string().optional(),
        serverSideCapture: z.string().optional(),
        description: z.string().optional()
      })).optional(),
      notes: z.string().optional()
    }
  },
  async (input: { devices: Array<{ deviceId: string; name: string; type: string; description?: string; configurations?: string[] }>; dataPath?: Array<{ hopIndex: number; deviceName?: string; clientSideCapture?: string; serverSideCapture?: string; description?: string }>; notes?: string }) => {
    const graphPath = process.env.PCAPAI_CASE_GRAPH_PATH;
    if (!graphPath) throw new Error("PCAPAI_CASE_GRAPH_PATH is required");
    const graph = JSON.parse(readFileSync(graphPath, "utf8")) as CaseGraph;
    const existing = graph.networkTopology || { devices: [], dataPath: [], notes: "" };
    graph.networkTopology = {
      devices: input.devices,
      dataPath: input.dataPath || existing.dataPath,
      notes: input.notes || existing.notes
    };
    writeFileSync(graphPath, JSON.stringify(graph, null, 2));
    return { content: [{ type: "text", text: `网络拓扑已更新：${input.devices.length} 个设备。` }] };
  }
);

function suggestNextQueries(graph: CaseGraph) {
  const suggestions: Array<{ question: string; reason: string; intent: string; params?: Record<string, unknown> }> = [];
  const activeQueryRun = (graph.queryRuns || []).find((run) => run.queryRunId === graph.activeQueryRunId);
  const diagnosis = activeQueryRun?.selectedDiagnosis;
  const path = activeQueryRun?.path;
  const correlations = activeQueryRun?.protocolCorrelations || [];
  const selectedConversation = activeQueryRun?.conversations.find((c) => c.conversationId === activeQueryRun.selectedConversationId);

  if (!graph.rawPackets.length && !graph.packets.length) {
    suggestions.push({ question: "请先上传 pcap 文件", reason: "当前案例没有可查询的抓包数据。", intent: "needs_clarification" });
    return suggestions;
  }

  if (!activeQueryRun) {
    if (graph.captures.length >= 2) {
      suggestions.push({ question: "这两个抓包文件能串起来吗？", reason: `有 ${graph.captures.length} 个抓包节点，可以尝试多文件关联。`, intent: "capture_correlation" });
    }
    if (graph.captures.length === 1) {
      suggestions.push({ question: "查看 TCP RST 和异常 session", reason: "还没有 QueryRun，可以先查看传输层异常事件。", intent: "protocol_event_query" });
    }
    suggestions.push({ question: "查看协议分布统计", reason: "了解抓包包含哪些协议，帮助缩小排查范围。", intent: "network_statistics" });
    return suggestions;
  }

  if (correlations.some((c) => c.kind === "dns_to_tcp")) {
    const dnsCorr = correlations.find((c) => c.kind === "dns_to_tcp");
    if (dnsCorr?.nextSteps?.length) {
      suggestions.push({ question: dnsCorr.nextSteps[0], reason: `DNS 关联发现：${dnsCorr.summary}`, intent: "tcp_session_query", params: { displayFilter: dnsCorr.targetDisplayFilter } });
    }
  }

  if (correlations.some((c) => c.kind === "http_host_to_tcp")) {
    const httpCorr = correlations.find((c) => c.kind === "http_host_to_tcp");
    if (httpCorr?.nextSteps?.length) {
      suggestions.push({ question: httpCorr.nextSteps[0], reason: `HTTP 关联发现：${httpCorr.summary}`, intent: "selected_session_diagnosis", params: { displayFilter: httpCorr.targetDisplayFilter } });
    }
  }

  if (correlations.some((c) => c.kind === "tls_sni_to_tcp")) {
    const tlsCorr = correlations.find((c) => c.kind === "tls_sni_to_tcp");
    if (tlsCorr?.nextSteps?.length) {
      suggestions.push({ question: tlsCorr.nextSteps[0], reason: `TLS 关联发现：${tlsCorr.summary}`, intent: "selected_session_diagnosis", params: { displayFilter: tlsCorr.targetDisplayFilter } });
    }
  }

  if (diagnosis?.checks.some((c) => c.key === "rst" && c.status === "problem")) {
    suggestions.push({ question: "RST 是从哪个方向发出的？", reason: "当前 session 存在 RST，需要确定方向来源。", intent: "selected_session_diagnosis" });
  }

  if (diagnosis?.checks.some((c) => c.key === "handshake" && c.status === "problem")) {
    suggestions.push({ question: "建连失败的服务端是否可达？", reason: "SYN 发出但未收到 SYN-ACK，可能是服务端或中间设备问题。", intent: "selected_session_diagnosis" });
  }

  if (path && path.hops.some((h) => h.status === "missing") && !graph.mappingHints.length) {
    const missingNodes = path.hops.filter((h) => h.status === "missing").map((h) => nodeName(graph, h.nodeId));
    suggestions.push({ question: "补充 NAT/F5/LB 代理映射线索", reason: `路径在 ${missingNodes.join("、")} 节点缺失，可能存在地址转换。`, intent: "mapping_hint_update" });
  }

  if (path && path.edges.some((e) => e.status === "needs_context")) {
    suggestions.push({ question: "补充时间偏移或抓包方向", reason: "相邻节点有时间窗口不重叠或需要补充映射。", intent: "mapping_hint_update" });
  }

  if (selectedConversation && selectedConversation.retransmissionCount > 3) {
    suggestions.push({ question: "重传集中在哪个时间段？", reason: `当前 session 有 ${selectedConversation.retransmissionCount} 个重传。`, intent: "selected_session_diagnosis" });
  }

  if (activeQueryRun.candidateGroups?.some((g) => g.failureCount > 0 && g.successCount > 0)) {
    const group = activeQueryRun.candidateGroups.find((g) => g.failureCount > 0 && g.successCount > 0);
    suggestions.push({ question: "成功的和失败的 session 有什么区别？", reason: `同一链路组有 ${group!.successCount} 成功、${group!.failureCount} 失败，对比差异可定位间歇性问题。`, intent: "selected_session_diagnosis" });
  }

  if (graph.captures.length >= 2 && !activeQueryRun.path?.hops.some((h) => h.status === "observed")) {
    suggestions.push({ question: "尝试跨节点关联", reason: "有多个抓包节点但当前 QueryRun 未形成跨节点路径。", intent: "capture_correlation" });
  }

  if (diagnosis?.findings.length && !suggestions.length) {
    suggestions.push({ question: "生成排障报告", reason: "已有足够的诊断结论，可以生成报告。", intent: "report_request" });
  }

  if (!suggestions.length) {
    suggestions.push({ question: "深入分析当前 session", reason: "可以进一步查看当前选中通讯对的详细行为。", intent: "selected_session_diagnosis" });
  }

  return suggestions.slice(0, 5);
}

server.registerTool(
  "suggest_next_query",
  {
    title: "Suggest next query",
    description: "基于当前 case graph 的证据模式，返回最多 5 个建议的后续查询。每个建议包含可执行的问题文本和推荐理由。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(suggestNextQueries(loadGraph())) }]
  })
);

server.registerTool(
  "get_insights",
  {
    title: "Get packet insights",
    description: "获取数据包洞察分析结果，包含连接生命周期异常、ACK 缺失、TCP 时序等问题。这些是在 pcap 上传时自动运行的分析结果。",
    inputSchema: {
      severity: z.enum(["info", "warning", "critical"]).optional().describe("按严重度过滤")
    }
  },
  async (input: { severity?: string }) => {
    const graph = loadGraph();
    const insights = (graph.insights || []) as Array<{
      insightId: string; type: string; severity: string;
      packetIds: string[]; description: string; detail: Record<string, unknown>;
      scenario?: string;
    }>;
    const filtered = input.severity ? insights.filter((i) => i.severity === input.severity) : insights;
    if (!filtered.length) {
      return { content: [{ type: "text", text: "暂无洞察分析结果。" }] };
    }
    const maxLines = 50;
    const capped = filtered.slice(0, maxLines);
    const lines = capped.map((insight) => {
      const sev = insight.severity === "critical" ? "严重" : insight.severity === "warning" ? "警告" : "信息";
      return `[${sev}] [${insight.type}] ${insight.description}${insight.scenario ? `\n  可能场景：${insight.scenario}` : ""}`;
    });
    const summary = filtered.length > maxLines
      ? `共 ${filtered.length} 条洞察（展示前 ${maxLines} 条）：\n\n${lines.join("\n\n")}\n\n...还有 ${filtered.length - maxLines} 条未展示。`
      : `共 ${filtered.length} 条洞察：\n\n${lines.join("\n\n")}`;
    return { content: [{ type: "text", text: summary }] };
  }
);

server.registerTool(
  "export_report",
  {
    title: "Export report",
    description: "导出基于当前 case graph 的 Markdown 报告草稿。只整理已有证据，不新增判断。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: reportMarkdown(loadGraph()) }]
  })
);

await server.connect(new StdioServerTransport());
