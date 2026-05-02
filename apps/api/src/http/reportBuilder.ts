import type { CaseGraph } from "../../../../packages/shared/src/index.js";

function nodeName(graph: CaseGraph, nodeId: string) {
  return graph.captures.find((capture) => capture.nodeId === nodeId)?.name || nodeId;
}

function compactLines(lines: string[]) {
  return lines.filter((line, index, source) => line || source[index - 1]).join("\n").trimEnd();
}

export function buildCaseReportMarkdown(graph: CaseGraph) {
  const activeQueryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId);
  if (!activeQueryRun) {
    return compactLines([
      `# ${graph.spec.title}`,
      "",
      "## 1. 当前状态",
      "- 尚未创建 QueryRun。",
      "- 请先通过 Agent 提出明确查询，例如“分析某时间段 A 到 B 的 443”或“列出 HTTP 4xx/5xx”。",
      "",
      "## 2. 数据来源",
      ...graph.captures.map((capture) => `- ${capture.name} (${capture.nodeId}): ${capture.pcapFilename || "-"}; ${capture.role}; ${capture.interfaceDirection}; ${capture.capturePosition || "-"}`),
      "",
      "## 3. 边界说明",
      "- 报告只基于当前 case 中已上传的 pcap 元信息，不做无证据推断。"
    ]);
  }

  const selectedConversation = activeQueryRun.conversations.find((conversation) => conversation.conversationId === activeQueryRun.selectedConversationId);
  const selectedDiagnosis = activeQueryRun.selectedDiagnosis;
  const selectedEvidence = activeQueryRun.evidenceCards.find((card) => card.cardId === activeQueryRun.selectedEvidenceCardId) || activeQueryRun.evidenceCards[0];
  const selectedGroup = activeQueryRun.candidateGroups.find((group) => group.groupId === activeQueryRun.selectedCandidateGroupId)
    || activeQueryRun.candidateGroups.find((group) => selectedConversation && group.conversationIds.includes(selectedConversation.conversationId));
  const relatedPacket = selectedEvidence?.frameNumber
    ? graph.packets.find((packet) => packet.frameNumber === selectedEvidence.frameNumber && packet.pcapFilename === selectedEvidence.pcapFilename)
    : undefined;
  const checks = selectedDiagnosis?.checks || [];
  const problemChecks = checks.filter((check) => check.status === "problem");
  const warnChecks = checks.filter((check) => check.status === "warn");
  const okChecks = checks.filter((check) => check.status === "ok");
  const nextSteps = [
    ...(selectedDiagnosis?.nextSteps || []),
    ...(activeQueryRun.path?.edges.flatMap((edge) => edge.nextSteps) || []),
    ...(activeQueryRun.protocolCorrelations.flatMap((correlation) => correlation.nextSteps) || [])
  ];
  const uniqueNextSteps = [...new Set(nextSteps)].filter(Boolean);
  const filters = [
    `- Query filter: ${activeQueryRun.displayFilter}`,
    selectedEvidence?.displayFilter ? `- 当前证据 filter: ${selectedEvidence.displayFilter}` : "",
    selectedEvidence?.packetDisplayFilter ? `- 定位帧 filter: ${selectedEvidence.packetDisplayFilter}` : "",
    selectedConversation?.displayFilter ? `- 当前 session filter: ${selectedConversation.displayFilter}` : "",
    ...activeQueryRun.protocolCorrelations.map((correlation) => `- ${correlation.kind}: ${correlation.targetDisplayFilter}`),
    ...(activeQueryRun.path?.hops || []).map((hop) => `- ${nodeName(graph, hop.nodeId)} hop: ${hop.wiresharkFilter}`)
  ].filter(Boolean);
  const toolRuns = (graph.toolRuns || []).slice(0, 12);

  return compactLines([
    `# ${graph.spec.title}`,
    "",
    "## 1. 问题与查询",
    `- 案例 ID: ${graph.spec.caseId}`,
    `- QueryRun: ${activeQueryRun.queryRunId}`,
    `- 用户问题: ${activeQueryRun.question || "-"}`,
    `- 查询协议: ${activeQueryRun.protocol || "-"}`,
    `- 查询条件: ${activeQueryRun.srcIp || "*"} -> ${activeQueryRun.dstIp || "*"}:${activeQueryRun.port ?? "*"} ${activeQueryRun.protocol || "*"}`,
    `- Query filter: ${activeQueryRun.displayFilter}`,
    "",
    "## 2. 数据来源",
    ...graph.captures.map((capture) => `- ${capture.name} (${capture.nodeId}): ${capture.pcapFilename || "-"}; ${capture.role}; ${capture.interfaceDirection}; ${capture.capturePosition || "-"}`),
    "",
    "## 3. 当前证据",
    ...(selectedEvidence ? [
      `- 证据: ${selectedEvidence.title}`,
      `- 摘要: ${selectedEvidence.summary}`,
      `- 证据类型: ${selectedEvidence.kind}`,
      `- 完整过滤器: ${selectedEvidence.displayFilter || "-"}`,
      `- 定位帧: ${selectedEvidence.packetDisplayFilter || (selectedEvidence.frameNumber ? `frame.number == ${selectedEvidence.frameNumber}` : "-")}`,
      `- pcap: ${selectedEvidence.pcapFilename || "-"}`,
      ...(relatedPacket ? [`- Packet: ${relatedPacket.srcIp || "*"}:${relatedPacket.srcPort ?? "*"} -> ${relatedPacket.dstIp || "*"}:${relatedPacket.dstPort ?? "*"}; ${relatedPacket.protocol}; ${relatedPacket.summary}`] : [])
    ] : ["- 当前 QueryRun 尚未生成证据卡。"]),
    "",
    "## 4. L7 关联",
    ...(activeQueryRun.protocolCorrelations.length ? activeQueryRun.protocolCorrelations.map((correlation) => `- ${correlation.kind}: ${correlation.summary}; filter=${correlation.targetDisplayFilter}; reasons=${correlation.reasons.join("；") || "-"}; next=${correlation.nextSteps.join("；") || "-"}`) : ["- 当前 QueryRun 尚未生成 L7-to-TCP 关联。"]),
    "",
    "## 5. 访问对象",
    ...(selectedConversation ? [
      `- Session: ${selectedConversation.srcIp}:${selectedConversation.srcPort} -> ${selectedConversation.dstIp}:${selectedConversation.dstPort}`,
      `- 协议/节点: ${selectedConversation.protocol}; ${nodeName(graph, selectedConversation.nodeId)}`,
      `- 时间范围: ${selectedConversation.startTime} - ${selectedConversation.endTime}`,
      `- 包数/字节: ${selectedConversation.packetCount} / ${selectedConversation.byteCount}`,
      `- RST/重传/Zero Window: ${selectedConversation.rstCount} / ${selectedConversation.retransmissionCount} / ${selectedConversation.zeroWindowCount}`,
      `- Session filter: ${selectedConversation.displayFilter}`
    ] : selectedEvidence ? [
      "- 当前 QueryRun 是协议证据查询，未选中具体 TCP conversation。",
      "- 证据卡已提供完整 flow/session filter，可在 Wireshark 中查看上下文。"
    ] : ["- 尚未选中访问对象。"]),
    "",
    "## 6. 多节点路径",
    ...(activeQueryRun.path?.hops.length ? activeQueryRun.path.hops.map((hop) => `- ${nodeName(graph, hop.nodeId)}: ${hop.status}; ${hop.observedTuple}; correlation=${hop.correlation}; reasons=${hop.correlationReasons.join("；") || "-"}; packets=${hop.packetCount}; filter=${hop.wiresharkFilter}`) : ["- 当前 QueryRun 尚未生成多节点路径。"]),
    "",
    "## 7. 路径边判断",
    ...(activeQueryRun.path?.edges.length ? activeQueryRun.path.edges.map((edge) => `- ${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}: ${edge.status}; ${edge.diagnosis || edge.label}; reasons=${edge.reasons.join("；") || "-"}; next=${edge.nextSteps.join("；") || "-"}${edge.timeDeltaSeconds !== undefined ? `; delta=${edge.timeDeltaSeconds.toFixed(3)}s` : ""}`) : ["- 当前 QueryRun 尚未生成路径边判断。"]),
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
    ...(selectedDiagnosis?.findings.length ? selectedDiagnosis.findings.flatMap((finding) => [
      `- ${finding.title} (${finding.confidence})`,
      `  - ${finding.summary}`,
      `  - 证据: ${finding.evidenceIds.join(", ") || "-"}`,
      `  - 下一步: ${finding.nextSteps.join("；") || "-"}`
    ]) : selectedEvidence ? ["- 当前证据用于说明协议/会话表现，不直接推断设备故障。"] : ["- 尚未生成判断结果。"]),
    "",
    "## 10. 候选链路上下文",
    ...(selectedGroup ? [
      `- 当前链路组: ${selectedGroup.summary}`,
      `- 成功/异常: ${selectedGroup.successCount} / ${selectedGroup.failureCount}`,
      `- 故障形态: ${selectedGroup.failureModes.map((mode) => `${mode.label} ${mode.count}`).join("；") || "-"}`
    ] : ["- 当前 QueryRun 未生成候选链路组。"]),
    "",
    "## 11. Wireshark 过滤器",
    ...filters,
    "",
    "## 12. 下一步动作",
    ...(uniqueNextSteps.length ? uniqueNextSteps.map((step) => `- ${step}`) : [
      "- 在 Wireshark 中打开当前证据 filter，查看定位帧前后的协议状态。",
      "- 补充抓包节点角色、抓包方向、抓包位置后再判断是否存在中间路径断点。"
    ]),
    "",
    "## 13. 执行轨迹",
    ...(toolRuns.length ? toolRuns.map((run) => `- ${run.createdAt} ${run.kind}/${run.status}: ${run.intent || run.target}; ${run.summary}${run.inputSummary ? `; input=${run.inputSummary}` : ""}${run.outputSummary ? `; output=${run.outputSummary}` : ""}${run.displayFilter ? `; filter=${run.displayFilter}` : ""}${run.durationMs !== undefined ? `; ${run.durationMs}ms` : ""}${run.error ? `; error=${run.error}` : ""}`) : ["- 尚无持久化 Planner / Tool / MCP 调用轨迹。"]),
    "",
    "## 14. 边界说明",
    "- 本报告只基于当前 QueryRun、当前证据卡、选中访问对象、路径边和 checks 生成。",
    "- 未覆盖的时间窗口、未上传的节点、未提供的 NAT/F5/LB/代理映射都不会被推断成确定故障点。",
    "- Agent 负责解释证据链；包级事实来自 tshark-query / case graph。"
  ]);
}
