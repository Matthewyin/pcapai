import type { AgentAnswer, CaseGraph, PacketSummary, QueryDiagnosis } from "../../../../packages/shared/src/index.js";
import type { AgentIntentPlan } from "../agents/runtime.js";
import { buildCaseReportMarkdown } from "../http/reportBuilder.js";

export function createAgentAnswerService(input: {
  evidencePacketSampleLimit: number;
}) {
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

  function queryRunAnswer(graph: CaseGraph, queryRunId: string): AgentAnswer {
    const queryRun = graph.queryRuns.find((run) => run.queryRunId === queryRunId);
    if (!queryRun) return fallbackAgentAnswer(graph);
    const selected = queryRun.conversations.find((conversation) => conversation.conversationId === queryRun.selectedConversationId);
    const selectedEvidence = queryRun.evidenceCards.find((card) => card.cardId === queryRun.selectedEvidenceCardId);
    const diagnosis = queryRun.selectedDiagnosis;
    const hasResult = Boolean(queryRun.conversations.length || queryRun.evidenceCards.length);
    const selectedGroup = queryRun.candidateGroups.find((group) => group.groupId === queryRun.selectedCandidateGroupId)
      || queryRun.candidateGroups.find((group) => selected && group.conversationIds.includes(selected.conversationId));
    const lines = [
      `当前 QueryRun：${queryRun.queryRunId}。`,
      `Wireshark 过滤器：${queryRun.displayFilter}`,
      queryRun.conversations.length
        ? `命中通讯对：${queryRun.totalConversationCount || queryRun.conversations.length} 个，聚合为候选访问链路 ${queryRun.candidateGroups.length || 0} 组。`
        : `命中协议证据：${queryRun.evidenceCards.length} 个。`,
      selectedGroup ? `当前访问链路组：${selectedGroup.summary}成功 ${selectedGroup.successCount} 条，异常 ${selectedGroup.failureCount} 条。` : "",
      selectedGroup?.failureModes.length ? `故障形态分布：${selectedGroup.failureModes.map((mode) => `${mode.label} ${mode.count} 条`).join("；")}` : "",
      selected ? `当前选中：${selected.srcIp}:${selected.srcPort} -> ${selected.dstIp}:${selected.dstPort}，${selected.packetCount} 个包。` : queryRun.evidenceCards.length ? "当前 QueryRun 是协议事件/transaction 查询，没有 TCP session 选中项。" : "当前没有可选通讯对。",
      selectedEvidence ? `当前证据卡：${selectedEvidence.title}；${selectedEvidence.summary}` : "",
      queryRun.protocolCorrelations.length ? `L7 关联：${queryRun.protocolCorrelations.length} 条；${queryRun.protocolCorrelations.map((correlation) => `${correlation.kind} -> ${correlation.targetDisplayFilter}`).join("；")}` : "",
      selected?.rankReasons.length ? `候选原因：${selected.rankReasons.join("；")}` : "",
      queryRun.path ? `路径：${queryRun.path.summary}` : "",
      diagnosis ? `诊断：${diagnosis.summary}` : "",
      diagnosis?.checks.length ? `诊断项：${diagnosis.checks.map((check) => `${check.label}=${check.status}`).join("；")}` : ""
    ].filter(Boolean);
    return {
      answer: lines.join("\n"),
      thoughts: [
        "读取当前 case captures。",
        "通过 tshark-query MCP 生成 display filter 并查询 TCP conversations。",
        "按 QueryRun 生成访问链路与证据卡片。"
      ],
      evidenceCards: queryRun.evidenceCards,
      actions: queryRun.evidenceCards.flatMap((card) => card.actions),
      evidenceIds: diagnosis?.evidence.map((event) => event.evidenceId) || [],
      packetIds: diagnosis?.diagnosticTags.flatMap((tag) => tag.packetIds) || [],
      sessionLinkIds: [],
      findingIds: diagnosis?.findings.map((finding) => finding.findingId) || [],
      missingContext: hasResult ? [] : ["当前查询没有命中通讯对或协议证据"],
      confidence: diagnosis?.confidence || (hasResult ? "high" : "needs_context"),
      suggestedActions: diagnosis?.nextSteps.length ? diagnosis.nextSteps : queryRun.conversations.length ? ["在右侧通讯对列表选择目标通讯对，查看路径和 Wireshark 过滤器。"] : hasResult ? ["点击证据卡片的 Wireshark 按钮查看协议证据。"] : ["放宽时间、地址或端口条件后重新查询。"],
      handoffAgent: queryRun.protocolCorrelations.length ? "ProtocolAgent" : queryRun.path ? "PathAgent" : "HypothesisAgent"
    };
  }

  function diagnosisPacketCards(queryRun: NonNullable<CaseGraph["queryRuns"][number]>, packets: PacketSummary[]) {
    const selected = queryRun.conversations.find((conversation) => conversation.conversationId === queryRun.selectedConversationId);
    if (!selected || !queryRun.selectedDiagnosis) return [];
    const packetById = new Map(packets.map((packet) => [packet.packetId, packet]));
    return queryRun.selectedDiagnosis.checks
      .filter((check) => check.status === "problem" || check.status === "warn")
      .flatMap((check) => check.packetIds.slice(0, 2).map((packetId) => ({ check, packet: packetById.get(packetId) })))
      .filter((item): item is { check: QueryDiagnosis["checks"][number]; packet: PacketSummary } => Boolean(item.packet))
      .map(({ check, packet }, index) => ({
        cardId: `diagnosis-packet-${queryRun.queryRunId}-${index + 1}`,
        kind: "packet" as const,
        title: `${check.label}证据 Frame ${packet.frameNumber}`,
        summary: check.summary,
        pcapFilename: packet.pcapFilename || selected.pcapFilename,
        frameNumber: packet.frameNumber,
        displayFilter: selected.displayFilter,
        packetDisplayFilter: `frame.number == ${packet.frameNumber}`,
        conversationId: selected.conversationId,
        queryRunId: queryRun.queryRunId,
        actions: ["open_wireshark"] as Array<"open_wireshark">
      }));
  }

  function activeQueryRunAnswer(graph: CaseGraph, question = ""): AgentAnswer {
    const queryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns[0];
    if (!queryRun) {
      return {
        answer: "当前还没有 QueryRun。请先提出明确访问查询，例如“分析 18:05:00 到 18:07:00，A 到 B 的 443”。",
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: ["缺少 QueryRun"],
        confidence: "needs_context",
        suggestedActions: ["先输入时间段、源地址、目的地址和端口，生成通讯对候选。"],
        handoffAgent: "DiagnosticInterviewAgent"
      };
    }
    if (/路径|链路|断点|哪一跳|上游|下游|边/.test(question) && !queryRun.path) {
      return {
        answer: `当前 active QueryRun ${queryRun.queryRunId} 没有生成 PathHop/PathEdge。它是 ${queryRun.protocol || "unknown"} 协议证据查询，不是 TCP 访问路径查询。请先提出包含源、目的、端口和时间范围的访问查询，或选择一个 TCP session 后再分析路径。`,
        thoughts: [
          "识别为路径/断点追问。",
          "读取 active QueryRun，发现没有 path 字段。",
          "不把协议证据查询伪造成访问路径。"
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: ["缺少 TCP QueryRun path", "缺少选中 TCP session"],
        confidence: "needs_context",
        suggestedActions: ["示例：分析 18:05:00 到 18:07:00，源 IP 到目的 IP 的 443 端口通信。"],
        handoffAgent: "PathAgent"
      };
    }
    const answer = queryRunAnswer(graph, queryRun.queryRunId);
    return {
      ...answer,
      answer: [
        `问题：${queryRun.question || "-"}`,
        answer.answer
      ].join("\n")
    };
  }

  function selectedSessionProblemAnswer(graph: CaseGraph): AgentAnswer {
    const queryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns[0];
    const selectedEvidence = queryRun?.evidenceCards.find((card) => card.cardId === queryRun.selectedEvidenceCardId) || queryRun?.evidenceCards[0];
    if (queryRun && selectedEvidence && !queryRun.selectedConversationId) {
      const diagnosis = queryRun.selectedDiagnosis;
      const relatedChecks = diagnosis?.checks.filter((check) => !check.packetIds.length || (selectedEvidence.frameNumber && check.packetIds.some((packetId) => graph.packets.some((packet) => packet.packetId === packetId && packet.frameNumber === selectedEvidence.frameNumber)))) || [];
      const lines = [
        `当前选中证据：${selectedEvidence.title}`,
        selectedEvidence.summary,
        `Wireshark filter：${selectedEvidence.displayFilter || "-"}`,
        selectedEvidence.packetDisplayFilter ? `定位帧：${selectedEvidence.packetDisplayFilter}` : "",
        relatedChecks.length ? `相关诊断项：${relatedChecks.map((check) => `${check.label}=${check.status}，${check.summary}`).join("；")}` : diagnosis?.checks.length ? `QueryRun 诊断项：${diagnosis.checks.map((check) => `${check.label}=${check.status}，${check.summary}`).join("；")}` : "",
        "判断边界：这是协议证据解释，不直接推断设备故障；需要结合底层 TCP session、抓包位置和时间窗口继续定位。"
      ].filter(Boolean);
      return {
        answer: lines.join("\n"),
        thoughts: [
          "识别为当前协议证据卡的故障追问。",
          "优先读取 active QueryRun 的 selectedEvidenceCardId。",
          "只基于证据卡、display filter 和确定性 checks 组织回答。"
        ],
        evidenceCards: [selectedEvidence],
        actions: selectedEvidence.actions,
        evidenceIds: [],
        packetIds: graph.packets.filter((packet) => packet.frameNumber === selectedEvidence.frameNumber).map((packet) => packet.packetId),
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: diagnosis?.confidence || "high",
        suggestedActions: ["点击 Wireshark 打开完整证据 filter，并查看定位帧前后的 TCP 状态。"],
        handoffAgent: "ProtocolAgent"
      };
    }
    if (!queryRun?.selectedConversationId || !queryRun.selectedDiagnosis) return activeQueryRunAnswer(graph);
    const selected = queryRun.conversations.find((conversation) => conversation.conversationId === queryRun.selectedConversationId);
    if (!selected) return activeQueryRunAnswer(graph);
    const diagnosis = queryRun.selectedDiagnosis;
    const problemChecks = diagnosis.checks.filter((check) => check.status === "problem");
    const warningChecks = diagnosis.checks.filter((check) => check.status === "warn");
    const okChecks = diagnosis.checks.filter((check) => check.status === "ok");
    const evidenceCards = diagnosisPacketCards(queryRun, graph.packets);
    const lines = [
      `当前选中 TCP session：${selected.srcIp}:${selected.srcPort} -> ${selected.dstIp}:${selected.dstPort}`,
      `结论：${diagnosis.summary}`,
      problemChecks.length ? `明确异常：${problemChecks.map((check) => `${check.label}：${check.summary}`).join("；")}` : "",
      warningChecks.length ? `需要复核：${warningChecks.map((check) => `${check.label}：${check.summary}`).join("；")}` : "",
      okChecks.length ? `未见异常项：${okChecks.map((check) => check.label).join("、")}` : "",
      `Wireshark filter：${selected.displayFilter}`,
      evidenceCards.length ? "右侧诊断项和本回答的证据卡片可直接打开完整 TCP session，并定位到对应 frame。" : "当前诊断项没有可定位 packet，建议先选择具体通讯对并重新精读。"
    ].filter(Boolean);
    return {
      answer: lines.join("\n"),
      thoughts: [
        "识别为当前选中 TCP session 的故障追问。",
        "优先读取 active QueryRun 的 selectedDiagnosis.checks。",
        "只基于确定性诊断项、证据包和 Wireshark filter 组织回答。"
      ],
      evidenceCards,
      actions: evidenceCards.flatMap((card) => card.actions),
      evidenceIds: diagnosis.evidence.map((event) => event.evidenceId),
      packetIds: [...new Set(diagnosis.checks.flatMap((check) => check.packetIds))],
      sessionLinkIds: [],
      findingIds: diagnosis.findings.map((finding) => finding.findingId),
      missingContext: [],
      confidence: diagnosis.confidence,
      suggestedActions: diagnosis.nextSteps.length ? diagnosis.nextSteps : ["点击诊断项证据包，在 Wireshark 中查看该 session 的上下文。"],
      handoffAgent: "PathAgent"
    };
  }

  function usageHelpAnswer(): AgentAnswer {
    return {
      answer: [
        "这个 Agent 的使用流程是：",
        "",
        "1. 新建会话",
        "点击左侧“新建会话”，系统会创建一个空 case。",
        "",
        "2. 上传 pcap",
        "把 pcap/pcapng/cap 拖到聊天输入框，或点回形针上传。上传后系统只读取元信息，不全量解析大包。",
        "",
        "3. 补充上下文",
        "说明抓包节点位置、入口/出口方向、是否有 NAT/F5/LB/代理/SSL 卸载、故障时间、源地址、目的地址和端口。",
        "",
        "4. 直接提问",
        "可以问：",
        "- 这个文件中有多少种协议？",
        "- 源 IP 排名、目的 IP 排名、端口分布是什么？",
        "- 给出前 10 个有 RST 的 TCP session pair。",
        "- 分析 18:05 到 18:07，A 到 B 的 443 访问。",
        "- 看看这两个文件是否能串起来。",
        "",
        "5. 看证据",
        "Agent 会创建 QueryRun 和 EvidenceCard。点击证据卡的 Wireshark 或复制过滤器，可回到包级证据。",
        "",
        "6. 继续追问或补包",
        "如果证据不足，Agent 会追问缺失上下文；如果缺少节点数据包，可以继续在聊天框追加上传。"
      ].join("\n"),
      thoughts: [
        "识别为使用帮助问题。",
        "不读取 active QueryRun，避免把历史查询结果误当作回答。",
        "返回产品主流程和可执行示例。"
      ],
      evidenceIds: [],
      packetIds: [],
      sessionLinkIds: [],
      findingIds: [],
      missingContext: [],
      confidence: "certain",
      suggestedActions: ["先上传 pcap，然后用故障时间、源/目的 IP、端口提出一次访问查询。"],
      handoffAgent: "DiagnosticInterviewAgent"
    };
  }

  function troubleshootingScopeAnswer(): AgentAnswer {
    return {
      answer: "要判断“哪里有问题”，需要先把查询范围收窄。请补充故障时间段、源 IP、目的 IP、端口，以及你关心的是建连失败、RST、重传、单向流量还是 Zero Window。",
      thoughts: [
        "识别为宽泛排障问题。",
        "当前没有 active QueryRun，直接跑 tcp 宽查询会慢且结论不可靠。",
        "先追问时间、源、目的、端口和故障现象。"
      ],
      evidenceIds: [],
      packetIds: [],
      sessionLinkIds: [],
      findingIds: [],
      missingContext: ["故障时间段", "源 IP", "目的 IP", "端口", "故障现象类型"],
      confidence: "needs_context",
      suggestedActions: [
        "示例：查询 HH:MM:SS 到 HH:MM:SS，源 IP 到目的 IP 的端口号重传连接。",
        "也可以先问：给出前10个有 reset 的 TCP session pair。"
      ],
      handoffAgent: "DiagnosticInterviewAgent"
    };
  }

  function reportAnswer(graph: CaseGraph): AgentAnswer {
    return {
      answer: buildCaseReportMarkdown(graph),
      thoughts: [
        "Leader Planner 识别为报告生成请求。",
        "报告基于当前 case graph、active QueryRun、EvidenceCard 和 checks 生成，不重新猜测全量故障。"
      ],
      evidenceIds: [],
      packetIds: graph.packets.map((packet) => packet.packetId).slice(0, input.evidencePacketSampleLimit),
      sessionLinkIds: [],
      findingIds: [],
      missingContext: graph.queryRuns.length ? [] : ["缺少 QueryRun，报告只能覆盖已上传文件和基础上下文"],
      confidence: graph.queryRuns.length ? "high" : "needs_context",
      suggestedActions: graph.queryRuns.length ? ["复制报告，或继续选择具体 EvidenceCard 下钻。"] : ["先提出一次明确查询，生成 QueryRun 后再导出报告。"],
      handoffAgent: "ReportAgent"
    };
  }

  function answerWithPlannerThought(answer: AgentAnswer, plan: AgentIntentPlan): AgentAnswer {
    const evidenceCards = answer.evidenceCards || [];
    const firstLine = answer.answer.split("\n").map((line) => line.trim()).find(Boolean) || "当前没有形成可解释的结论。";
    const shouldCompact = evidenceCards.length > 0 && answer.answer.length > 800;
    const compactAnswer = shouldCompact ? [
      "问题：已按当前输入生成可回溯分析结果。",
      `判断：${firstLine}`,
      evidenceCards.length ? `证据：已生成 ${evidenceCards.length} 张 EvidenceCard；前 ${Math.min(5, evidenceCards.length)} 张为 ${evidenceCards.slice(0, 5).map((card) => `「${card.title}」`).join("、")}。` : "",
      answer.confidence ? `置信度：${answer.confidence}` : "",
      answer.missingContext.length ? `缺失上下文：${answer.missingContext.join("；")}` : "",
      answer.suggestedActions.length ? `下一步：${answer.suggestedActions.join("；")}` : "",
      "明细请在证据卡、当前查询和右侧执行轨迹中下钻。"
    ].filter(Boolean).join("\n") : answer.answer;
    return {
      ...answer,
      answer: compactAnswer,
      thoughts: [
        `规划：${plan.intent}（${plan.confidence}）${plan.reason ? `，${plan.reason}` : ""}`,
        ...(plan.missingContext.length ? [`规划缺失上下文：${plan.missingContext.join("、")}`] : []),
        ...(answer.thoughts || [])
      ]
    };
  }

  return {
    queryRunAnswer,
    selectedSessionProblemAnswer,
    usageHelpAnswer,
    activeQueryRunAnswer,
    fallbackAgentAnswer,
    troubleshootingScopeAnswer,
    reportAnswer,
    answerWithPlannerThought
  };
}
