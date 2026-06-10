import type { AgentAnswer, CaseGraph, PacketSummary, QueryDiagnosis } from "../../../../packages/shared/src/index.js";
import type { AgentIntentPlan } from "../agents/runtime.js";
import { buildCaseReportMarkdown } from "../http/reportBuilder.js";

export function createAgentAnswerService(input: {
  evidencePacketSampleLimit: number;
}) {
  function reviewableEvidenceCards(answer: AgentAnswer): NonNullable<AgentAnswer["evidenceCards"]> {
    return (answer.evidenceCards || []).map((card) => {
      const reviewQuery = card.reviewQuery || card.packetDisplayFilter || card.displayFilter || (card.frameNumber ? `frame.number == ${card.frameNumber}` : undefined);
      const coverage = card.coverage || [
        card.queryRunId ? `QueryRun ${card.queryRunId}` : "",
        card.pcapFilename ? `文件 ${card.pcapFilename}` : "",
        card.conversationId ? `会话 ${card.conversationId}` : "",
        card.frameNumber ? `Frame ${card.frameNumber}` : ""
      ].filter(Boolean).join("；") || "当前证据卡未声明覆盖范围。";
      const reviewNotes = card.reviewNotes?.length ? card.reviewNotes : [
        card.displayFilter ? `会话/事件过滤器：${card.displayFilter}` : "",
        card.packetDisplayFilter ? `包级过滤器：${card.packetDisplayFilter}` : "",
        card.frameNumber ? `可定位到 Frame ${card.frameNumber}` : ""
      ].filter(Boolean);
      return { ...card, coverage, reviewQuery, reviewNotes };
    });
  }

  function hasReviewSections(text: string) {
    return ["判断：", "证据：", "反证：", "置信度：", "下一步："].every((label) => text.includes(label));
  }

  function formatReviewableAnswer(answer: AgentAnswer): AgentAnswer {
    if (hasReviewSections(answer.answer)) return { ...answer, evidenceCards: reviewableEvidenceCards(answer) };
    const evidenceCards = reviewableEvidenceCards(answer);
    const evidenceLine = evidenceCards.length
      ? `已生成 ${evidenceCards.length} 张证据卡；可打开详情复制 display filter、定位 frame 或进入 Wireshark 复核。`
      : answer.packetIds.length || answer.evidenceIds.length
        ? `packetIds=${answer.packetIds.length}，evidenceIds=${answer.evidenceIds.length}。`
        : "当前没有可复核证据；需要先补齐上下文或创建 QueryRun。";
    const counterEvidence = answer.missingContext.length
      ? `仍缺少 ${answer.missingContext.join("、")}，因此不能排除其他路径或设备因素。`
      : evidenceCards.length
        ? "未单独形成反向证据结论；请用证据卡过滤器复核返回方向、相邻节点和相反事件。"
        : "没有足够证据支持或排除具体故障点。";
    return {
      ...answer,
      evidenceCards,
      answer: [
        "判断：",
        answer.answer || "当前没有形成明确判断。",
        "",
        "证据：",
        evidenceLine,
        "",
        "反证：",
        counterEvidence,
        "",
        "置信度：",
        answer.confidence || "needs_context",
        "",
        "下一步：",
        answer.suggestedActions.length ? answer.suggestedActions.map((action, index) => `${index + 1}. ${action}`).join("\n") : "补充故障时间、源/目的地址、端口和抓包位置后继续分析。"
      ].join("\n")
    };
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

  function diagnosticInterviewAnswer(graph: CaseGraph, question: string, missingContext: string[] = []): AgentAnswer {
    const captureLines = graph.captures.length
      ? graph.captures.map((capture) => {
        const packetText = typeof capture.packetCount === "number" ? `${capture.packetCount} 包` : "包数未知";
        const timeText = capture.firstPacketTime && capture.lastPacketTime
          ? `${new Date(capture.firstPacketTime * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })} 到 ${new Date(capture.lastPacketTime * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })}`
          : "时间范围未知";
        return `- ${capture.name || capture.nodeId}：${packetText}，${timeText}`;
      })
      : ["- 还没有上传 pcap 文件"];
    const nodeQuestions = graph.captures.length > 1
      ? [
        "这几个 pcap 分别在哪个节点抓的？",
        "节点顺序是什么？中间是否有 NAT、F5、SSL 卸载、代理或负载均衡？",
        "如果有地址转换，请补充转换前后的 IP/端口；如果时间不同步，请补充时间偏移。"
      ]
      : [
        "这个 pcap 是在哪个节点抓的？是客户端侧、服务端侧还是中间设备？",
        "抓包方向是入口、出口还是双向？"
      ];
    const followUpQuestions = [
      graph.captures.length ? "你要分析的是哪一次访问？请给出故障时间段、源 IP、目的 IP、端口或协议。" : "请先上传 pcap/pcapng/cap 文件。",
      ...nodeQuestions,
      "故障现象是什么？例如超时、RST、重传、DNS 失败、TLS 握手失败、HTTP 5xx 或访问慢。"
    ];
    return {
      answer: [
        "当前还不能直接下结论，需要先补齐排障上下文。",
        "",
        "已知数据：",
        ...captureLines,
        "",
        "需要你补充：",
        ...followUpQuestions.map((item, index) => `${index + 1}. ${item}`),
        "",
        "补齐后我再创建 QueryRun，用 tshark 查询证据，并按“判断 / 证据 / 反证 / 置信度 / 下一步”给出结果。"
      ].join("\n"),
      thoughts: [
        "识别为排障访谈阶段。",
        "当前上下文不足，先追问故障目标、抓包位置和路径转换信息。",
        "暂不执行宽查询，避免生成无法评判的统计噪音。"
      ],
      evidenceIds: [],
      packetIds: [],
      sessionLinkIds: [],
      findingIds: [],
      missingContext: [...new Set(missingContext.length ? missingContext : followUpQuestions)],
      confidence: "needs_context",
      suggestedActions: followUpQuestions,
      followUpQuestions,
      diagnosticPhase: "interview",
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
    // 帮助、报告和追问类回答是面向用户的完整文本，不套「判断/证据/反证」复核模板
    if (plan.intent === "usage_help" || plan.intent === "report_request" || plan.intent === "needs_clarification") {
      return {
        ...answer,
        thoughts: [
          `规划：${plan.intent}（${plan.confidence}）${plan.reason ? `，${plan.reason}` : ""}`,
          ...(plan.missingContext.length ? [`规划缺失上下文：${plan.missingContext.join("、")}`] : []),
          ...(answer.thoughts || [])
        ]
      };
    }
    const reviewableAnswer = formatReviewableAnswer(answer);
    const evidenceCards = reviewableAnswer.evidenceCards || [];
    const firstLine = reviewableAnswer.answer.split("\n").map((line) => line.trim()).find((line) => line && !["判断：", "证据：", "反证：", "置信度：", "下一步："].includes(line)) || "当前没有形成可解释的结论。";
    const shouldCompact = evidenceCards.length > 0 && reviewableAnswer.answer.length > 1200;
    const compactAnswer = shouldCompact ? [
      "问题：已按当前输入生成可回溯分析结果。",
      `判断：${firstLine}`,
      evidenceCards.length ? `证据：已生成 ${evidenceCards.length} 张 EvidenceCard；前 ${Math.min(5, evidenceCards.length)} 张为 ${evidenceCards.slice(0, 5).map((card) => `「${card.title}」`).join("、")}。` : "",
      `反证：${reviewableAnswer.missingContext.length ? `仍缺少 ${reviewableAnswer.missingContext.join("、")}。` : "请用证据卡过滤器复核相反方向和相邻节点。"} `,
      reviewableAnswer.confidence ? `置信度：${reviewableAnswer.confidence}` : "",
      reviewableAnswer.suggestedActions.length ? `下一步：${reviewableAnswer.suggestedActions.join("；")}` : "",
      "明细请在证据卡、当前查询和右侧执行轨迹中下钻。"
    ].filter(Boolean).join("\n") : reviewableAnswer.answer;
    return {
      ...reviewableAnswer,
      answer: compactAnswer,
      thoughts: [
        `规划：${plan.intent}（${plan.confidence}）${plan.reason ? `，${plan.reason}` : ""}`,
        ...(plan.missingContext.length ? [`规划缺失上下文：${plan.missingContext.join("、")}`] : []),
        ...(reviewableAnswer.thoughts || [])
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
    diagnosticInterviewAnswer,
    reportAnswer,
    answerWithPlannerThought
  };
}
