# pcapAI 设计方案

## 目标

pcapAI 是一个 Agent-first 本地浏览器工作台，用于离线分析网络故障。

用户上传 pcap 并用自然语言提问后，Chain Planner 生成单步或多步分析计划，确定性 protocol adapter 运行 tshark 查询产出 evidence cards，Leader Agent 综合解读证据链并给出诊断结论。Agent 通过 case-graph MCP 只读 case graph，通过 tshark-query MCP 查询原始包数据，不直接解析原始 pcap。

## 系统范围

支持的分析类型：

- TCP 连接异常：SYN 丢失、SYN 无 SYN-ACK、RST、重传、Zero Window、单向流量、窗口趋势、RST 方向、握手重试、延迟 ACK、连接洪泛、段异常、Keepalive、吞吐量、TCP 选项
- NAT/代理检测：七层代理识别（Via/XFF 头、SSL 卸载模式、TCP 连接分离）、NAT 启发式检测（多目标连接模式、ISN 跳跃、孤立 SYN）
- DNS 解析异常：NXDOMAIN、SERVFAIL、无响应、查询突发、Zone Transfer、截断响应、成功率统计
- TLS 握手问题：ClientHello/ServerHello 缺失、Alert、版本/SNI 异常、弃用协议、弱加密套件、证书 SAN 不匹配、会话恢复、ALPN、重协商
- HTTP 状态异常：4xx/5xx 响应、延迟异常、重定向链、Host/SNI 不匹配、错误突发、认证失败、压缩缺失
- ICMP 错误：Unreachable、TTL Exceeded、Fragmentation、PMTU 黑洞、Traceroute 模式、Echo 丢包/RTT 统计
- UDP 流异常：多端口访问、单向流、QUIC 检测
- QUIC 连接：版本分布、握手分析、版本不匹配
- NTP 时间同步：Stratum 分布、高 Stratum 检测、Root Delay 统计
- SSH 会话：消息分布、断开检测、认证重试
- 跨协议链路时序分析（DNS→TCP→TLS→HTTP 完整瀑布图）
- 多节点跨链路关联
- 开放性异常分析（Chain Planner 自动编排多步计划）

系统支持：

- 多节点 pcap/pcapng 上传
- 手工录入 MappingHint（NAT、SLB、代理、网关、隧道）
- Chain Planner 动态生成 1-5 步分析链（不硬编码任何故障场景）
- 6 个确定性 protocol adapter（TCP/DNS/TLS/HTTP/ICMP/UDP）
- 29 个确定性 insight 分析器（TCP/ICMP/HTTP/TLS/DNS/UDP/QUIC/NTP/SSH + L7 代理检测 + NAT 启发式检测），无阈值过滤，完整报告所有检测到的模式
- Protocol adapter 自改进：三层路由（hardcoded regex → learned patterns → agent fallback）
- Leader Agent + 5 个 handoff subagent（Triage/Evidence/Path/Protocol/Report）
- Agent 同时使用 case-graph MCP 和 tshark-query MCP
- TCP Stream 跟踪（`tshark -z follow,tcp`）+ 客户端/服务端双列展示
- 跨协议瀑布图（纯 SVG）+ 网络拓扑图（纯 SVG）
- SSE 流式输出，链式步骤进度实时展示
- 聊天气泡 Markdown 渲染 + 证据卡片在新标签页展示（Blob URL）
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
6. 前端在聊天气泡展示文字分析（Markdown 渲染），在新标签页展示证据卡片（display filter、Wireshark 按钮）。
7. 用户在新标签页点击任何 card → 本地 Wireshark 打开对应 filter。
8. 用户可点击建议的后续查询继续下钻，或导出报告。

## 数据模型

核心数据契约由 `packages/shared/src/index.ts` 定义。

- `CaseSpec`：case 名称、协议。
- `CaptureNode`：节点名、角色、pcap 文件、接口方向、包数、时间范围。
- `MappingHint`/`TimeOffsetHint`：NAT/SLB/代理/时间偏移线索。
- `PacketSummary`：frame number、timestamp、五元组、协议字段、TLS/DNS/HTTP/ICMP/QUIC/NTP/SSH 详情。
- `Conversation`：TCP 通讯对统计。
- `QueryRun`：一次查询的完整结果——display filter、conversations、candidateGroups、evidenceCards、selectedDiagnosis（checks）、protocolCorrelations。
- `QueryPath`：跨节点路径还原（PathHop/PathEdge）。
- `EvidenceCard`：可点击的证据卡，包含 Wireshark filter。
- `ProtocolCorrelation`：L7 协议到 TCP 的关联（DNS→TCP、TLS SNI→TCP、HTTP Host→TCP、ICMP→TCP、HTTP 跨连接 `http_to_http`）。
- `ConnectionLink`：七层代理/SSL 卸载场景中两条独立 TCP 连接的关联（前端→代理 / 代理→后端），包含关联方法（HTTP URI/Cookie/Timing/SSL 卸载/时序模式/手工）。
- `PacketInsight`：确定性分析器产出的诊断洞察，由 insightEngine 生成。
- `AnalysisChainPlan`/`AnalysisChainStep`：分析链计划。
- `AgentAnswer`：Agent 回复——answer、evidenceCards、checks、suggestedQueries、protocolCorrelations。

## 分析原则

- **确定性优先**：protocol adapter 运行 tshark 直接产出证据，不依赖 LLM。
- **三层路由**：hardcoded regex → learned patterns（`data/learned_patterns.json`）→ agent fallback（tshark-query MCP）。
- **HTTP 跨连接关联**：HTTP adapter 同时生成 L7→TCP 和 `http_to_http` 跨连接关联，用于识别同一请求出现在两条不同 TCP 连接（客户端→代理 / 代理→后端）的场景。
- **自改进**：agent fallback 后 LLM 生成 regex pattern + adapterId，持久化供下次确定性路由使用。无硬编码映射。
- **链式编排**：Chain Planner 动态规划多步计划，步骤间通过 `paramsFrom` JSON 路径表达式传递参数，不硬编码场景。
- **Graph reload**：链式执行中每步完成后刷新 case graph，后续步骤可读到前序步骤写入的 QueryRun。
- **Agent 只读 graph + tshark**：Agent 通过 case-graph MCP 读取 case graph，通过 tshark-query MCP 查询原始包数据。不修改证据、不解析 pcap 文件、不执行 shell。
- **综合解读**：链的最后一个步骤由 LLM 综合前序步骤的 QueryRun evidenceCards 和 checks，给出诊断结论。如果没有 LLM key，系统只输出确定性统计结果。
- **聊天是读结论的地方，链接页是操作 Wireshark 的地方**：聊天气泡保留所有文字分析（Markdown 渲染），证据卡片在新标签页展示（Blob URL）。
- **Insight 引擎无阈值过滤**：29 个确定性分析器报告所有检测到的模式，severity 仅作为视觉标记，不做阈值过滤。

## 置信度策略

- `certain`：确定性管线产出，多个 packet 事实支撑。
- `high`：多个事实或明确 mapping hint 支撑，没有明显反证。
- `low`：缺少关键上下文或只有单侧证据。
- `needs_context`：缺接口方向、节点角色、时间窗口等，不能给确定结论。

没有证据时不输出确定结论。缺失观察必须标明覆盖范围和前提。
