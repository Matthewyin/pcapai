# pcapAI 设计方案

## 目标

pcapAI 是一个 Agent-first 本地浏览器工作台，用于离线分析网络故障。

用户上传 pcap 并用自然语言提问后，Chain Planner 生成单步或多步分析计划，确定性 protocol adapter 运行 tshark 查询产出 evidence cards，Leader Agent 综合解读证据链并给出诊断结论。Agent 只读取 case graph（包含所有 QueryRun 及其 evidenceCards、checks、protocolCorrelations），不直接解析原始 pcap。

## 系统范围

支持的分析类型：

- TCP 连接异常：SYN 丢失、SYN 无 SYN-ACK、RST、重传、Zero Window、单向流量
- DNS 解析失败：NXDOMAIN、SERVFAIL、无响应
- TLS 握手问题：ClientHello/ServerHello 缺失、Alert、版本/SNI 异常
- HTTP 状态异常：4xx/5xx 响应、延迟异常
- ICMP 错误：Unreachable、TTL Exceeded、Fragmentation
- UDP 流异常
- 多节点跨链路关联
- 开放性异常分析（Chain Planner 自动编排多步计划）

系统支持：

- 多节点 pcap/pcapng 上传
- 手工录入 MappingHint（NAT、SLB、代理、网关、隧道）
- Chain Planner 动态生成 1-5 步分析链（不硬编码任何故障场景）
- 6 个确定性 protocol adapter（TCP/DNS/TLS/HTTP/ICMP/UDP）
- Leader Agent + 5 个 handoff subagent（Triage/Evidence/Path/Protocol/Report）
- SSE 流式输出，链式步骤进度实时展示
- 一键 Wireshark 打开证据
- Markdown 报告导出
- 后续查询建议（suggest_next_query）

系统不做：

- 实时抓包
- Agent 直接读取 pcap 或运行 shell
- 自研底层 pcap decoder

## 用户流程

1. 用户在浏览器新建会话，上传 pcap。
2. 用户在聊天框用自然语言提问（如"帮我分析异常"或"查看 DNS 解析失败"）。
3. Chain Planner 规划分析步骤（单步或多步）。
4. 确定性步骤运行 tshark 查询，产出 evidence cards + diagnosis checks。
5. 如有 LLM key，Agent 综合解读前序步骤的证据，给出诊断结论和建议。
6. 前端展示 evidence cards、诊断检查、后续查询建议。
7. 用户点击任何 card → 本地 Wireshark 打开对应 filter。
8. 用户可点击建议的后续查询继续下钻，或导出报告。

## 数据模型

核心数据契约由 `packages/shared/src/index.ts` 定义。

- `CaseSpec`：case 名称、协议。
- `CaptureNode`：节点名、角色、pcap 文件、接口方向、包数、时间范围。
- `MappingHint`/`TimeOffsetHint`：NAT/SLB/代理/时间偏移线索。
- `PacketSummary`：frame number、timestamp、五元组、协议字段、TLS/DNS/HTTP/ICMP 详情。
- `Conversation`：TCP 通讯对统计。
- `QueryRun`：一次查询的完整结果——display filter、conversations、candidateGroups、evidenceCards、selectedDiagnosis（checks）、protocolCorrelations。
- `QueryPath`：跨节点路径还原（PathHop/PathEdge）。
- `EvidenceCard`：可点击的证据卡，包含 Wireshark filter。
- `ProtocolCorrelation`：L7 协议到 TCP 的关联（DNS→TCP、TLS SNI→TCP、HTTP Host→TCP）。
- `AnalysisChainPlan`/`AnalysisChainStep`：分析链计划。
- `AgentAnswer`：Agent 回复——answer、evidenceCards、checks、suggestedQueries。

## 分析原则

- **确定性优先**：protocol adapter 运行 tshark 直接产出证据，不依赖 LLM。
- **链式编排**：Chain Planner 动态规划多步计划，步骤间通过 `paramsFrom` JSON 路径表达式传递参数，不硬编码场景。
- **Graph reload**：链式执行中每步完成后刷新 case graph，后续步骤可读到前序步骤写入的 QueryRun。
- **Agent 只读**：Agent 通过 case-graph MCP 读取 case graph（包括所有 QueryRun），不修改证据、不解析 pcap、不执行 shell。
- **综合解读**：链的最后一个步骤由 LLM 综合前序步骤的 QueryRun evidenceCards 和 checks，给出诊断结论。如果没有 LLM key，系统只输出确定性统计结果。

## 置信度策略

- `certain`：确定性管线产出，多个 packet 事实支撑。
- `high`：多个事实或明确 mapping hint 支撑，没有明显反证。
- `low`：缺少关键上下文或只有单侧证据。
- `needs_context`：缺接口方向、节点角色、时间窗口等，不能给确定结论。

没有证据时不输出确定结论。缺失观察必须标明覆盖范围和前提。
