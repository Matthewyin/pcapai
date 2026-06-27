import { tool, type Tool } from "@openai/agents";
import { z } from "zod";
import type { CaseGraph, CaseMemory, QueryRun } from "../../../../packages/shared/src/index.js";
import { DataPathHopSchema, NetworkDeviceSchema } from "../../../../packages/shared/src/index.js";
import { buildCaseReportMarkdown } from "../http/reportBuilder.js";
import { extractPacketFeatures, searchFieldNotes, type FieldNoteHit } from "../services/fieldNotesService.js";
import { listSkills, getSkill, createSkill } from "../services/skillsService.js";
import { apiConfig } from "../config.js";

// case graph 只读/记忆工具：原 case-graph MCP 的进程内实现。
// 读工具直接访问内存中的 graph；写工具（拓扑、记忆）通过 saveGraph 落到真实 caseStore，
// 不再经过临时快照文件（旧实现会在会话结束时把 agent 写入的记忆一起删掉）。

type CaseGraphToolsInput = {
  loadGraph: () => CaseGraph;
  saveGraph: (graph: CaseGraph) => void;
};

function endpoint(ip?: string, port?: number) {
  return ip && port !== undefined ? `${ip}:${port}` : "";
}

function canonicalPair(first: string, second: string) {
  return first && second ? [first, second].sort().join(" <-> ") : "";
}

function activeQueryRunOf(graph: CaseGraph) {
  return graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId);
}

// 限制 QueryRun 返回体积，防止大会话列表撑爆 LLM context
function slimQueryRun(run: QueryRun) {
  return {
    ...run,
    conversations: run.conversations.map((c) => ({
      conversationId: c.conversationId,
      srcIp: c.srcIp, srcPort: c.srcPort, dstIp: c.dstIp, dstPort: c.dstPort,
      protocol: c.protocol, packetCount: c.packetCount, byteCount: c.byteCount,
      rstCount: c.rstCount, retransmissionCount: c.retransmissionCount, zeroWindowCount: c.zeroWindowCount,
      displayFilter: c.displayFilter
    })),
    candidateGroups: run.candidateGroups.map((g) => ({ groupId: g.groupId, summary: g.summary, conversationIds: g.conversationIds })),
    evidenceCards: run.evidenceCards.map((card) => ({ cardId: card.cardId, kind: card.kind, title: card.title, displayFilter: card.displayFilter }))
  };
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

function packetTimeRangeStats(packets: Array<{ timestamp?: number }>) {
  const timestamps = packets.map((packet) => packet.timestamp).filter((timestamp): timestamp is number => Number.isFinite(timestamp));
  if (!timestamps.length) {
    return { packetCount: packets.length, timestampCount: 0, startEpoch: null, endEpoch: null, startIso: null, endIso: null, startBeijing: null, endBeijing: null, durationSeconds: null };
  }
  const startEpoch = Math.min(...timestamps);
  const endEpoch = Math.max(...timestamps);
  return {
    packetCount: packets.length,
    timestampCount: timestamps.length,
    startEpoch,
    endEpoch,
    // UTC ISO 保留给机器/调试使用；面向用户输出请优先使用 startBeijing/endBeijing。
    startIso: new Date(startEpoch * 1000).toISOString(),
    endIso: new Date(endEpoch * 1000).toISOString(),
    startBeijing: formatBeijingTime(startEpoch),
    endBeijing: formatBeijingTime(endEpoch),
    durationSeconds: Math.max(0, endEpoch - startEpoch)
  };
}

function caseStatistics(graph: CaseGraph) {
  const activeQueryRun = activeQueryRunOf(graph);
  return {
    tcp: tcpCommunicationStats(graph),
    diagnostics: diagnosticStats(graph),
    queryRuns: {
      total: graph.queryRuns.length,
      activeQueryRunId: graph.activeQueryRunId || null,
      activeConversationCount: activeQueryRun?.conversations.length || 0,
      activeTotalConversationCount: activeQueryRun?.totalConversationCount || activeQueryRun?.conversations.length || 0,
      activeCandidateGroupCount: activeQueryRun?.candidateGroups.length || 0,
      selectedConversationId: activeQueryRun?.selectedConversationId || null
    },
    timeRanges: {
      allCapturedPackets: packetTimeRangeStats(graph.rawPackets || []),
      filteredPackets: packetTimeRangeStats(graph.packets || [])
    }
  };
}

function graphSummary(graph: CaseGraph) {
  const activeQueryRun = activeQueryRunOf(graph);
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
      queryRuns: graph.queryRuns.length,
      insights: graph.insights.length,
      mappingHints: graph.mappingHints.length,
      timeOffsetHints: graph.timeOffsetHints.length
    },
    statistics: caseStatistics(graph),
    captures: graph.captures.map(({ nodeId, name, role, interfaceDirection, capturePosition }) => ({ nodeId, name, role, interfaceDirection, capturePosition })),
    path: graph.path,
    findings: graph.findings.map(({ findingId, title, confidence, evidenceIds, packetIds, nextSteps }) => ({ findingId, title, confidence, evidenceIds, packetIds, nextSteps })),
    evidence: graph.evidence.map(({ evidenceId, kind, title, nodeId, packetIds, confidence }) => ({ evidenceId, kind, title, nodeId, packetIds, confidence })),
    sessionLinks: graph.sessionLinks.map(({ linkId, fromNodeId, toNodeId, fromSegmentId, toSegmentId, confidence, score }) => ({ linkId, fromNodeId, toNodeId, fromSegmentId, toSegmentId, confidence, score })),
    diagnosticTags: (graph.diagnosticTags || []).map(({ tagId, kind, nodeIds, segmentIds, evidenceIds, confidence, summary }) => ({ tagId, kind, nodeIds, segmentIds, evidenceIds, confidence, summary })),
    activeQueryRun: activeQueryRun ? slimQueryRun(activeQueryRun) : null
  };
}

function nodeName(graph: CaseGraph, nodeId: string) {
  return graph.captures.find((capture) => capture.nodeId === nodeId)?.name || nodeId;
}

function suggestNextQueries(graph: CaseGraph) {
  const suggestions: Array<{ question: string; reason: string; intent: string; params?: Record<string, unknown> }> = [];
  const activeQueryRun = activeQueryRunOf(graph);
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

  for (const kind of ["dns_to_tcp", "http_host_to_tcp", "tls_sni_to_tcp"] as const) {
    const correlation = correlations.find((c) => c.kind === kind);
    if (correlation?.nextSteps?.length) {
      suggestions.push({
        question: correlation.nextSteps[0],
        reason: `${kind} 关联发现：${correlation.summary}`,
        intent: kind === "dns_to_tcp" ? "tcp_session_query" : "selected_session_diagnosis",
        params: { displayFilter: correlation.targetDisplayFilter }
      });
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
  const mixedGroup = activeQueryRun.candidateGroups.find((g) => g.failureCount > 0 && g.successCount > 0);
  if (mixedGroup) {
    suggestions.push({ question: "成功的和失败的 session 有什么区别？", reason: `同一链路组有 ${mixedGroup.successCount} 成功、${mixedGroup.failureCount} 失败，对比差异可定位间歇性问题。`, intent: "selected_session_diagnosis" });
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

function formatInsights(graph: CaseGraph, severity?: string) {
  const insights = severity ? graph.insights.filter((i) => i.severity === severity) : graph.insights;
  if (!insights.length) return "暂无洞察分析结果。";
  const maxLines = 50;
  const lines = insights.slice(0, maxLines).map((insight) => {
    const sev = insight.severity === "critical" ? "严重" : insight.severity === "warning" ? "警告" : "信息";
    return `[${sev}] [${insight.type}] ${insight.description}${insight.scenario ? `\n  可能场景：${insight.scenario}` : ""}`;
  });
  return insights.length > maxLines
    ? `共 ${insights.length} 条洞察（展示前 ${maxLines} 条）：\n\n${lines.join("\n\n")}\n\n...还有 ${insights.length - maxLines} 条未展示。`
    : `共 ${insights.length} 条洞察：\n\n${lines.join("\n\n")}`;
}

function defaultCaseMemory(): CaseMemory {
  return { topology: "", findings: [], userNotes: [] };
}

// 实战知识库候选格式化：明确标注"候选、需验证"，防止 Agent 直接套用。
// 候选只是先验提示，Agent 必须用抓包+RFC 验证后才能下结论。
// candidateCause 带 skillIds 时提示 Agent 调 get_skill 读取操作 SOP（方法论层）。
function formatFieldNoteHits(hits: FieldNoteHit[]): string {
  if (!hits.length) return "未在实战知识库中匹配到已知排障案例。请基于抓包和 RFC 自主推理。";
  const lines = hits.map((hit, index) => {
    const causes = hit.note.candidateCauses.map((cause) => {
      const rfc = cause.rfcDocId ? `RFC ${cause.rfcDocId}${cause.rfcSection ? `§${cause.rfcSection}` : ""}` : "无 RFC 依据（经验推测）";
      const skillHint = cause.skillIds?.length ? `\n      推荐技能（调 get_skill 读取操作步骤）：${cause.skillIds.join(", ")}` : "";
      return `    - [${cause.likelihood}] ${cause.cause}（${rfc}）\n      验证方法：${cause.howToVerify}${skillHint}`;
    }).join("\n");
    return `[候选${index + 1}]（特征匹配度 ${hit.featureScore}）${hit.note.title}\n  摘要：${hit.note.summary}\n  候选真因：\n${causes}`;
  });
  return `以下已知排障案例可能相关（均为候选，需你用抓包+RFC 验证，不可直接套用）：\n\n${lines.join("\n\n")}`;
}

export function createCaseGraphTools(input: CaseGraphToolsInput): Tool[] {
  const json = (value: unknown) => JSON.stringify(value);
  return [
    tool({
      name: "load_case_graph",
      description: "读取当前 case graph 摘要，不返回完整 packet 列表。",
      parameters: z.object({}),
      execute: async () => json(graphSummary(input.loadGraph()))
    }),
    tool({
      name: "get_case_statistics",
      description: "读取确定性统计结果，例如 TCP 通信对数量、诊断标签统计、捕获数据包整体时间范围。",
      parameters: z.object({}),
      execute: async () => json(caseStatistics(input.loadGraph()))
    }),
    tool({
      name: "search_field_notes",
      description: "从当前抓包特征检索实战知识库，返回已知排障案例候选（现象→候选真因→RFC 引用）。建议在排障开始时优先调用，用候选指导后续抓包/RFC 验证。候选仅为提示，必须验证后才能下结论。特征不命中时可用 question 做关键词兜底。",
      parameters: z.object({
        question: z.string().optional().describe("当前用户问题，特征不命中时用于关键词兜底检索")
      }),
      execute: async ({ question }) => {
        // 失败降级：知识库未构建或检索异常时返回空，不阻塞 Agent 自主推理。
        try {
          const features = extractPacketFeatures(input.loadGraph());
          const hits = searchFieldNotes(features, apiConfig.fieldNotes.topK, question);
          return formatFieldNoteHits(hits);
        } catch {
          return "实战知识库暂不可用，请基于抓包和 RFC 自主推理。";
        }
      }
    }),
    tool({
      name: "list_skills",
      description: "列出所有可用的排障技能（Skills，方法论层 SOP）。Skills 比实战知识库更抽象，描述可复用的操作流程（如\"如何验证 TCP options\"）。实战库命中后可按其 skillIds 调 get_skill 读取详细步骤。",
      parameters: z.object({}),
      execute: async () => {
        try {
          const skills = listSkills();
          if (!skills.length) return "暂无可用技能。";
          const lines = skills.map((s) => `- ${s.name}：${s.description}${s.triggers?.length ? `（触发：${s.triggers.join("、")}）` : ""}`);
          return `可用技能（${skills.length} 个）：\n${lines.join("\n")}\n\n用 get_skill(name) 读取具体执行步骤。`;
        } catch {
          return "技能库暂不可用。";
        }
      }
    }),
    tool({
      name: "get_skill",
      description: "读取指定技能的完整执行步骤（SOP）。当实战知识库命中的候选真因引用了某 skill，或 list_skills 看到匹配当前问题的技能时调用。",
      parameters: z.object({ name: z.string().describe("技能名，如 verify-tcp-options") }),
      execute: async ({ name }) => {
        try {
          const skill = getSkill(name);
          if (!skill) return `未找到技能：${name}。用 list_skills 查看可用技能。`;
          return `# 技能：${skill.name}\n描述：${skill.description}\n${skill.triggers?.length ? `触发场景：${skill.triggers.join("、")}\n` : ""}${skill.toolsRequired?.length ? `依赖工具：${skill.toolsRequired.join(", ")}\n` : ""}\n${skill.body}`;
        } catch {
          return `技能 ${name} 读取失败。`;
        }
      }
    }),
    tool({
      name: "create_skill",
      description: "把验证有效的排障操作流程固化为新技能（自我进化）。当你执行了一套行之有效的步骤且可复用时调用。技能名用 kebab-case（如 verify-mtu-blackhole）。",
      parameters: z.object({
        name: z.string().describe("技能名，kebab-case，如 verify-tcp-options"),
        description: z.string().describe("一句话说明用途"),
        triggers: z.array(z.string()).optional().describe("触发场景描述列表"),
        toolsRequired: z.array(z.string()).optional().describe("依赖的工具名列表"),
        body: z.string().describe("正文：适用场景、执行步骤、判定标准，markdown 格式"),
        overwrite: z.boolean().optional().describe("已存在时是否覆盖，默认 false")
      }),
      execute: async ({ name, description, triggers, toolsRequired, body, overwrite }) => {
        try {
          const result = createSkill({ name, description, triggers, toolsRequired, body, overwrite });
          return result.created
            ? `技能 ${name} 已${overwrite ? "更新" : "创建"}：${result.filePath}`
            : `技能 ${name} 未创建：${result.reason}`;
        } catch (error) {
          return error instanceof Error ? `技能创建失败：${error.message}` : "技能创建失败。";
        }
      }
    }),
    tool({
      name: "get_query_runs",
      description: "读取当前案例的 QueryRun 摘要列表（不含完整 conversations 和 packets）。",
      parameters: z.object({}),
      execute: async () => json(input.loadGraph().queryRuns.map((run) => ({
        queryRunId: run.queryRunId,
        question: run.question,
        conversationCount: run.conversations.length,
        evidenceCardCount: run.evidenceCards.length,
        protocolCorrelationCount: run.protocolCorrelations.length,
        diagnosisChecks: run.selectedDiagnosis?.checks.map((c) => ({ key: c.key, label: c.label, status: c.status, summary: c.summary }))
      })))
    }),
    tool({
      name: "get_query_run",
      description: "按 queryRunId 读取通讯对、路径和 Wireshark filter。",
      parameters: z.object({ queryRunId: z.string() }),
      execute: async ({ queryRunId }) => {
        const run = input.loadGraph().queryRuns.find((item) => item.queryRunId === queryRunId);
        return json(run ? slimQueryRun(run) : null);
      }
    }),
    tool({
      name: "get_active_query_run",
      description: "读取当前激活的 QueryRun。",
      parameters: z.object({}),
      execute: async () => {
        const run = activeQueryRunOf(input.loadGraph());
        return json(run ? slimQueryRun(run) : null);
      }
    }),
    tool({
      name: "get_conversation",
      description: "在当前 QueryRun 中按 conversationId 读取通讯对。",
      parameters: z.object({ conversationId: z.string() }),
      execute: async ({ conversationId }) => json(input.loadGraph().queryRuns.flatMap((run) => run.conversations).find((conversation) => conversation.conversationId === conversationId) || null)
    }),
    tool({
      name: "get_query_diagnosis",
      description: "读取当前 QueryRun 的 selectedDiagnosis，包括 checks、findings 和 nextSteps。",
      parameters: z.object({}),
      execute: async () => json(activeQueryRunOf(input.loadGraph())?.selectedDiagnosis || null)
    }),
    tool({
      name: "get_path_diagnosis",
      description: "读取当前 QueryRun 的 PathHop、PathEdge 和边判断。",
      parameters: z.object({}),
      execute: async () => json(activeQueryRunOf(input.loadGraph())?.path || null)
    }),
    tool({
      name: "get_protocol_correlations",
      description: "读取当前 QueryRun 的 DNS/TLS/HTTP 到 TCP 的确定性关联。",
      parameters: z.object({}),
      execute: async () => json(activeQueryRunOf(input.loadGraph())?.protocolCorrelations || [])
    }),
    tool({
      name: "get_evidence_cards",
      description: "读取当前 QueryRun 的证据卡片。",
      parameters: z.object({}),
      execute: async () => json(activeQueryRunOf(input.loadGraph())?.evidenceCards || [])
    }),
    tool({
      name: "get_finding",
      description: "按 findingId 读取判断结果。",
      parameters: z.object({ findingId: z.string() }),
      execute: async ({ findingId }) => json(input.loadGraph().findings.find((finding) => finding.findingId === findingId) || null)
    }),
    tool({
      name: "get_evidence",
      description: "按 evidenceId 读取证据事件。",
      parameters: z.object({ evidenceId: z.string() }),
      execute: async ({ evidenceId }) => json(input.loadGraph().evidence.find((event) => event.evidenceId === evidenceId) || null)
    }),
    tool({
      name: "get_session_link",
      description: "按 sessionLinkId 读取跨节点会话关联。",
      parameters: z.object({ sessionLinkId: z.string() }),
      execute: async ({ sessionLinkId }) => json(input.loadGraph().sessionLinks.find((link) => link.linkId === sessionLinkId) || null)
    }),
    tool({
      name: "get_packet_detail",
      description: "按 packetId 读取数据包详情。",
      parameters: z.object({ packetId: z.string() }),
      execute: async ({ packetId }) => {
        const graph = input.loadGraph();
        return json(graph.packets.find((packet) => packet.packetId === packetId) || graph.rawPackets.find((packet) => packet.packetId === packetId) || null);
      }
    }),
    tool({
      name: "explain_path",
      description: "读取当前 QueryRun 的通讯路径 hop。",
      parameters: z.object({}),
      execute: async () => {
        const run = activeQueryRunOf(input.loadGraph());
        return json({ queryRun: run ? slimQueryRun(run) : null, path: run?.path || null });
      }
    }),
    tool({
      name: "get_network_topology",
      description: "读取用户提供的网络拓扑和数据路径信息。包括网络设备（防火墙、LB、WAF、SSL 等）和抓包位置。",
      parameters: z.object({}),
      execute: async () => {
        const topology = input.loadGraph().networkTopology;
        return topology ? json(topology) : "当前案例尚未收集网络拓扑信息。请在诊断访谈中向用户询问网络路径和抓包位置。";
      }
    }),
    tool({
      name: "update_network_topology",
      description: "保存从用户对话中提取的网络拓扑信息。包括网络设备和数据路径。",
      parameters: z.object({
        devices: z.array(NetworkDeviceSchema),
        dataPath: z.array(DataPathHopSchema).optional(),
        notes: z.string().optional()
      }),
      execute: async ({ devices, dataPath, notes }) => {
        const graph = input.loadGraph();
        const existing = graph.networkTopology || { devices: [], dataPath: [], notes: "" };
        input.saveGraph({ ...graph, networkTopology: { devices, dataPath: dataPath || existing.dataPath, notes: notes || existing.notes } });
        return `网络拓扑已更新：${devices.length} 个设备。`;
      }
    }),
    tool({
      name: "suggest_next_query",
      description: "基于当前 case graph 的证据模式，返回最多 5 个建议的后续查询。每个建议包含可执行的问题文本和推荐理由。",
      parameters: z.object({}),
      execute: async () => json(suggestNextQueries(input.loadGraph()))
    }),
    tool({
      name: "get_insights",
      description: "获取数据包洞察分析结果，包含连接生命周期异常、ACK 缺失、TCP 时序等问题。这些是在 pcap 上传时自动运行的分析结果。",
      parameters: z.object({ severity: z.enum(["info", "warning", "critical"]).optional().describe("按严重度过滤") }),
      execute: async ({ severity }) => formatInsights(input.loadGraph(), severity)
    }),
    tool({
      name: "export_report",
      description: "导出基于当前 case graph 的 Markdown 报告草稿。只整理已有证据，不新增判断。",
      parameters: z.object({}),
      execute: async () => buildCaseReportMarkdown(input.loadGraph())
    }),
    tool({
      name: "get_case_memory",
      description: "读取当前案例的记忆：已确认的网络拓扑、已记录的关键发现（含帧号/重传明细）、用户补充信息。追问时优先调用此工具获取已有结论。",
      parameters: z.object({}),
      execute: async () => json(input.loadGraph().memory || defaultCaseMemory())
    }),
    tool({
      name: "update_case_memory",
      description: "更新案例记忆。用于保存网络拓扑、用户补充信息、关键发现（findings）。findings 会被追加，用于记录具体帧号/重传明细/RFC 引用等，后续追问可直接引用。",
      parameters: z.object({
        topology: z.string().optional(),
        userNotes: z.string().optional(),
        findings: z.array(z.string()).optional().describe("关键发现列表，每条是一个可被追问引用的事实（如'端口58487↔54038有4次重传：Frame 1234/1235/1236/1237'）")
      }),
      execute: async ({ topology, userNotes, findings }) => {
        const graph = input.loadGraph();
        const memory: CaseMemory = { ...defaultCaseMemory(), ...graph.memory };
        if (topology) memory.topology = topology;
        // userNotes 与 findings 追加后做 cap（避免长生命周期 case 无限堆积，保留最近 50 条）
        if (userNotes) memory.userNotes = [...memory.userNotes, userNotes];
        if (findings && findings.length) memory.userNotes = [...memory.userNotes, ...findings.map((f) => `[发现] ${f}`)];
        if (memory.userNotes.length > 50) memory.userNotes = memory.userNotes.slice(-50);
        input.saveGraph({ ...graph, memory });
        return json({ updated: true, memory });
      }
    })
  ];
}
