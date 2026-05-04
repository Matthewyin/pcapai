# pcapAI 架构

## 架构概览

pcapAI 是 Agent-first 本地浏览器工作台，用于离线分析网络故障。主流程以 `POST /api/cases/:caseId/agent/stream` 为准：用户上传 pcap 并提问 → Insight Engine 确定性分析 → Chain Planner (LLM) 规划分析链 → 确定性 protocol adapter 运行 tshark 产出证据 → 必要时 Leader Agent 通过 MCP 工具综合解读证据链 → SSE 输出诊断结论。

## 系统架构图

```mermaid
flowchart TB
  subgraph Web["apps/web — React 工作台"]
    UI["聊天界面<br/>SSE 流式输出"]
  end

  subgraph API["apps/api — Express + Agent Runtime"]
    Router["routes.ts<br/>REST + SSE 端点"]
    Planner["Chain Planner<br/>(LLM / 本地兜底)"]
    ChainExec["executeChain<br/>链式执行引擎"]
    Adapters["Protocol Adapters<br/>TCP/DNS/TLS/HTTP/ICMP/UDP"]
    InsightEng["Insight Engine<br/>29 个确定性分析器"]
    PatternLearner["Pattern Learner"]
    CaseStore["caseStore<br/>data/cases/:id/case.json"]
  end

  subgraph LLM["LLM Provider"]
    Model["OpenAI 兼容 API<br/>(Doubao/Claude/GPT)"]
  end

  subgraph AgentRuntime["Agent Runtime (OpenAI Agents SDK)"]
    Leader["Leader Agent"]
    Triage["DiagnosticInterview<br/>Agent"]
    Hypo["Hypothesis<br/>Agent"]
    PathA["Path<br/>Agent"]
    Proto["Protocol<br/>Agent"]
    Report["Report<br/>Agent"]
    Leader --> Triage
    Leader --> Hypo
    Leader --> PathA
    Leader --> Proto
    Leader --> Report
  end

  subgraph MCP["MCP Servers (stdio)"]
    CG["case-graph MCP<br/>20 个工具"]
    TQ["tshark-query MCP<br/>19 个工具"]
    EO["evidence-opener MCP<br/>1 个工具"]
  end

  subgraph External["外部工具"]
    Tshark["tshark"]
    Wireshark["Wireshark"]
  end

  UI -->|"HTTP / SSE"| Router
  Router -->|"planChain()"| Planner
  Planner -->|"AnalysisChainPlan"| ChainExec
  Planner --> LLM
  ChainExec -->|"单步路由"| Adapters
  ChainExec -->|"llm_explain"| AgentRuntime
  Router -->|"agent fallback"| AgentRuntime
  AgentRuntime --> LLM

  Adapters -->|"tsharkQueryClient"| TQ
  AgentRuntime --> CG
  AgentRuntime --> TQ
  Router --> EO

  TQ --> Tshark
  EO --> Wireshark

  CG -->|"读取"| CaseStore
  Router -->|"loadGraphWithInsights"| InsightEng
  InsightEng -->|"写回 insights"| CaseStore
  Adapters -->|"写入 QueryRun"| CaseStore
  ChainExec -->|"reloadGraph"| CaseStore

  Router -->|"agent 成功后"| PatternLearner
  PatternLearner --> LLM

  Shared["packages/shared<br/>Zod Schema + TypeScript 类型"] -.-> API
  Shared -.-> Web
  Shared -.-> MCP
  Config["config/defaults.json<br/>PCAPAI_* 环境变量"] -.-> API
  Config -.-> Web
  Config -.-> MCP
```

## 请求处理流程

```
用户提问
  ↓
1. loadGraphWithInsights() — 懒运行 Insight Engine（29 个确定性分析器）
  ↓
2. Chain Planner (LLM 或本地正则兜底) → AnalysisChainPlan
  ↓
3a. chain 路径 (planKind=chain):
    executeChain → 逐步执行，每步后 reloadGraph
    确定性步骤 → protocol adapter → tshark → evidenceCards
    llm_explain 步骤 → Leader Agent → handoff subagent
    无 llm_explain → 自动追加 LLM 综合解读
  ↓
3b. single 确定性路径:
    protocol adapter 三层路由:
      hardcoded regex → tshark 查询
      learned pattern → tshark 查询
      无匹配 → agent fallback (Leader Agent + case-graph + tshark-query MCP)
    → evidenceCards + checks + protocolCorrelations → 写入 QueryRun
  ↓
3c. llm_explain 路径:
    Leader Agent → handoff → subagent
    → case-graph MCP 读取 case graph
    → tshark-query MCP 查询原始包数据
    → 诊断结论 + suggestedQueries
  ↓
4. SSE 流式输出 → Web 聊天气泡
```

## 组件详解

### `apps/api` — Express API + Agent Runtime

#### HTTP 层 (`src/http/`)
- **routes.ts** — REST 端点 + SSE 流式 agent 回答：
  1. `loadGraphWithInsights()` 懒运行 Insight Engine
  2. `planChain()` 规划分析链
  3. `executeChain()` 逐步执行，每步后 `reloadGraph()` 刷新 case graph
  4. 无 `llm_explain` 步骤时自动追加 LLM 综合解读
  5. agent fallback 成功后异步触发 Pattern Learner
- **caseStore.ts** — case 持久化：`data/cases/:caseId/case.json`
- **capturePreprocess.ts** — 通过 `editcap -s` 裁剪 payload
- **reportBuilder.ts** — 从 case graph 生成结构化 Markdown 报告
- **llmSettings.ts** — LLM 配置文件管理（`.env` 中 `PCAPAI_LLM_PROFILE_*`）

#### Agent 层 (`src/agents/`)
- **runtime.ts** — OpenAI Agents SDK runtime：
  - `runChainPlanner()` — 规划分析链，输出 `AnalysisChainPlan`
  - `runIntentPlanner()` — 单步意图分类，用于普通 `/agent` 路径；无 LLM 时由 `plannerService.ts` 本地兜底
  - `runPcapTroubleshootingAgent()` — Leader Agent + 5 个 handoff subagent：
    - **DiagnosticInterviewAgent** — 诊断访谈，收集故障现象、网络拓扑、抓包位置
    - **HypothesisAgent** — 假设验证，优先读取 insights，再按需调用 tshark-query MCP
    - **PathAgent** — 多节点路径分析和跨链路关联
    - **ProtocolAgent** — 协议级行为分析，可直接调用 tshark-query MCP 查询原始包数据
    - **ReportAgent** — 生成结构化诊断报告
  - Leader Agent 和所有 subagent 同时挂载 case-graph MCP 和 tshark-query MCP；Chain Planner Agent 不使用 MCP
  - MCP 连接方式：`MCPServerStdio`，每次 `runPcapTroubleshootingAgent` 调用时创建临时 case graph JSON 文件并通过 `PCAPAI_CASE_GRAPH_PATH` 环境变量传给 case-graph MCP
  - 返回 `AgentAnswerWithToolCalls`，包含 tool call 名称用于 pattern learning

#### Planner 层 (`src/services/`)
- **plannerService.ts** — 分析链执行引擎：
  - `createPlannerService()` — 工厂函数，接收 12 个 intent handler
  - `planChain()` / `planUserIntent()` — 规划（LLM 或本地兜底）
  - `executeChain()` — 逐步执行，支持 `paramsFrom` 参数绑定 + `reloadGraph` 回调
  - `executeChainStep()` — 单步 intent 路由（12 种 intent）
  - 本地兜底模式：无 LLM key 时使用正则匹配
- **patternLearner.ts** — protocol adapter 自改进模块：
  - `loadLearnedPatterns()` — 从 `data/learned_patterns.json` 加载 learned regex→adapterId 对
  - `learnFromAgentRun()` — agent fallback 后，用 LLM 生成 regex + adapterId；验证后持久化
  - 无硬编码 tool→adapter 映射，LLM 从问题上下文和 adapter 列表决定路由

#### Protocol Adapters (`src/protocolAdapters/`)
6 个确定性 adapter，绕过 LLM 直接运行 tshark：
- **tcp.ts** — RST session pairs、retransmission pairs、zero-window pairs、SYN-no-SYN/ACK、one-way traffic、TCP issues overview
- **dns.ts** — DNS 失败/无响应事务，rcode 分组，多 check 输出
- **tls.ts** — TLS 握手事件（ClientHello/ServerHello/Alert），握手完整性检查，多 check 输出
- **http.ts** — HTTP 事务（4xx/5xx），请求/响应匹配，多 check 输出，跨连接关联
- **icmp.ts** — ICMP Unreachable/TTL Exceeded/Fragmentation
- **udp.ts** — UDP 流聚合
- 共享逻辑在 `builders.ts`：packet pair 分组、evidence card 创建、L7→TCP protocol correlations（DNS→TCP、TLS SNI→TCP、HTTP Host→TCP、ICMP→TCP）以及 HTTP 跨连接关联（`http_to_http`，用于七层代理/SSL 卸载场景）
- `types.ts` 中 `runProtocolAdapter()` 实现三层路由：hardcoded regex → learned patterns → null（由调用方 fallback 到 agent）

#### Insight Engine (`src/services/insightEngine.ts`)
29 个确定性分析器，在 `routes.ts` 的 `loadGraphWithInsights()` 中懒运行：仅在 `graph.packets.length > 0` 且当前 graph 没有 `insights` 时执行，结果写回 case graph。不在 `runtime.ts` 内部运行，不会在每次请求都强制重算。无阈值过滤，所有检测到的模式均报告：
- **TCP（12 个）**：连接生命周期、ACK Gap、TCP 时序（RTT/空闲/突发）、窗口趋势、RST 方向、握手重试、延迟 ACK、连接洪泛、段异常、Keepalive、吞吐量、TCP 选项
- **ICMP（2 个）**：Echo 配对（丢包/RTT）、ICMP 高级（Unreachable/PMTU/Traceroute/Redirect）
- **HTTP（4 个）**：状态链（重定向/5xx/4xx）、Header 异常（未匹配/混合端口）、Timing、高级（Host/SNI/错误突发/认证/压缩/Cache-Control/WebSocket/Content-Length/XFF）
- **TLS（2 个）**：握手 Alert、高级（版本/密码套件/证书/会话恢复/ALPN/重协商）
- **DNS（2 个）**：异常（无响应/NXDOMAIN/SERVFAIL/耗时）、高级（突发/成功率/AXFR/截断/TTL/CNAME/Zone Transfer）
- **跨协议**：cross_protocol_chain（DNS→TCP→TLS→HTTP 瀑布图）
- **UDP（1 个）**：多端口/突发/单向流/QUIC 检测
- **新协议**：QUIC（连接概览/握手/版本）、NTP（Stratum/延迟）、SSH（消息分布/断开/认证/版本）
- **NAT/L7 代理检测（2 个）**：L7 Proxy Detection（Via/XFF 头检测、SSL 卸载模式、TCP 连接分离）、NAT Heuristic（多目标连接模式、ISN 跳跃、孤立 SYN）

### `apps/web` — React 工作台

单文件 React 19 应用（`src/main.tsx`）。聊天优先布局：
- 会话历史、消息流、底部输入框
- pcap 上传（文件选择 / 拖放 / 粘贴）
- Markdown 渲染（`marked` + `dompurify`）用于已完成的 assistant 消息
- 证据卡片在浏览器新标签页展示（Blob URL，"查看证据详情" 按钮）——聊天气泡保留文字分析，链接页用于 Wireshark 操作
- SSE 流式 agent 回答
- 链式步骤进度（chain_start → step_start → step_done → chain_done）
- TCP stream 查看器（列表→内容下钻，客户端/服务端双列展示）
- 跨协议瀑布图（纯 SVG，DNS/TCP/TLS/HTTP 时序可视化）
- 网络拓扑图（纯 SVG，节点与边）
- Insight 诊断模式渲染
- Mapping hint / time offset hint 编辑
- LLM 设置管理（profile CRUD + 连通性测试）
- 深色/浅色主题切换
- 报告导出

### `packages/shared` — 共享 schema (`@pcapai/shared`)

Zod schema + TypeScript 类型，定义完整领域模型：
- `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`
- `PacketSummary`（含 QUIC/NTP/SSH 字段）, `Conversation`
- `QueryRun`, `QueryPath`, `EvidenceCard`
- `ProtocolCorrelation`（含 `http_to_http` 跨连接关联类型）, `AccessCandidateGroup`, `PacketInsight`
- `ConnectionLink` — 七层代理/SSL 卸载场景中两条独立 TCP 连接的关联（前端→代理 / 代理→后端）
- `AnalysisChainPlan`, `AnalysisChainStep`, `ChainStepResult`
- `AgentAnswer`（含 `protocolCorrelations` 字段）, `QueryDiagnosis`
- `CaseGraph` — 聚合所有上述数据（含 `connectionLinks`、`insights`）

### `config/defaults.json` — 集中配置

所有运行时默认值：API host/port（默认 `30022`）、CORS、MCP 启动命令、LLM 设置（默认 Doubao/ByteDance Ark）、tshark 配置、查询限制、诊断阈值。所有值可通过 `PCAPAI_*` 环境变量覆盖。

### MCP 服务器

三个基于 stdio 的 MCP 服务器（`@modelcontextprotocol/sdk`），由 API 和 Agent Runtime 通过 `MCPServerStdio` 连接：

#### `mcp/tshark-query` — tshark 查询引擎（19 个工具）
被两个调用方使用：
- **API 层**（`tsharkQueryClient.ts`）：protocol adapter 和 routes.ts 直接调用 tshark 查询
- **Agent Runtime**：Leader Agent 和 subagent 通过 MCP 协议调用，查询原始包数据

工具：`build_display_filter`、`get_capture_time_range`、`list_protocols`、`get_network_statistics`、`list_tcp_conversations`、`query_packets`、`get_conversation_packets`、`get_tshark_packet_detail`、`list_tcp_resets`、`list_tcp_retransmissions`、`list_tcp_zero_window`、`list_icmp_events`、`list_dns_packets`、`list_udp_packets`、`list_tls_packets`、`list_http_packets`、`list_tcp_streams`、`follow_tcp_stream`、`get_expert_info`

#### `mcp/evidence-opener` — Wireshark 打开器（1 个工具）
仅被 API 层（`evidenceOpenerClient.ts`）调用。用 pcap 路径 + display filter 打开本地 Wireshark。不分析数据包。
- 工具：`open_in_wireshark`

#### `mcp/case-graph` — Agent 的 case graph 工具层（20 个工具）
仅被 Agent Runtime 调用。从临时 JSON 文件（`PCAPAI_CASE_GRAPH_PATH`）读取 case graph。大多数工具只读；`update_network_topology` 写入临时快照，不直接修改持久化文件。

工具：`load_case_graph`、`get_case_statistics`、`get_query_runs`、`get_query_run`、`get_active_query_run`、`get_conversation`、`get_query_diagnosis`、`get_path_diagnosis`、`get_protocol_correlations`、`get_evidence_cards`、`get_finding`、`get_evidence`、`get_session_link`、`get_packet_detail`、`explain_path`、`get_network_topology`、`update_network_topology`、`suggest_next_query`、`get_insights`、`export_report`

## 查询管线

### 流式 Agent 查询（`POST /api/cases/:caseId/agent/stream`）

```
用户问题
  ↓
1. loadGraphWithInsights() — 懒运行 Insight Engine
  ↓
2. Chain Planner 分类 → AnalysisChainPlan
  ↓
3a. Chain path (planKind=chain):
    executeChain → 逐步执行
    每步后 reloadGraph 刷新 case graph
    支持 paramsFrom 参数绑定
    无 llm_explain 步骤 → 自动追加 LLM 综合解读
  ↓
3b. Single deterministic path:
    protocol adapter 三层路由:
      hardcoded regex match → tshark 查询
      learned pattern match → tshark 查询
      无匹配 → agent fallback (case-graph + tshark-query MCP)
    → evidenceCards + checks + protocolCorrelations
    → 写入 QueryRun
  ↓
3c. Agent path (llm_explain intent):
    Leader Agent → handoff → subagent
    → 通过 case-graph MCP + tshark-query MCP
    → 诊断结论 + suggestedQueries
```

普通 `POST /api/cases/:caseId/agent` 仍保留单步兼容路径：`planUserIntent()` → `executeAgentIntentPlan()` → 必要时 `runPcapTroubleshootingAgent()`。它不完全等同于上面的 Chain Planner 主路径。

### QueryRun 创建（`POST /api/cases/:caseId/query-runs`）

```
1. 推断或接受时间/地址/端口/协议 filter
2. tshark-query MCP → display filter
3. tshark-query MCP → tshark 查询 → conversations + packet evidence
4. API 构建 AccessCandidateGroups + QueryPath + QueryDiagnosis
5. 存储 QueryRun + selectedConversation + path + diagnosis + evidenceCards
6. 浏览器展示证据卡片
```

## Protocol Adapter 自改进

Protocol adapter 路由采用三层 fallback：

1. **Hardcoded regex** — 每个 adapter 有内置的 match 函数
2. **Learned patterns** — `data/learned_patterns.json` 存储 `{regex, adapterId}` 对，由 LLM 在 agent fallback 后生成
3. **Agent fallback** — leader agent 通过 tshark-query MCP 处理查询；成功后 `patternLearner` 用 LLM 生成新 regex pattern

学习模块（`src/services/patternLearner.ts`）无硬编码 tool→adapter 映射。LLM 从问题上下文和可用 adapter 列表决定 regex 和 adapterId。

## 分析链执行

### 12 种 Intent

| Intent | 处理方式 |
|--------|---------|
| `usage_help` | 返回使用帮助 |
| `protocol_statistics` | 确定性统计查询 |
| `network_statistics` | 确定性网络事件查询 |
| `mapping_hint_update` | 更新 mapping hint 并重跑关联 |
| `capture_correlation` | 多文件关联查询 |
| `protocol_event_query` | 协议事件查询（三层路由 + agent fallback） |
| `tcp_session_query` | TCP session 查询 |
| `selected_session_diagnosis` | 当前 session 诊断追问 |
| `active_query_explain` | 当前 QueryRun 解释 |
| `report_request` | 报告生成 |
| `needs_clarification` | 需要更多上下文 |
| `llm_explain` | LLM 综合解读 |

### Graph Reload

链式执行中每步完成后 `reloadGraph()` 刷新 case graph，后续步骤可读到前序步骤写入的 QueryRun。

### 自动综合

当分析链无 `llm_explain` 步骤但配置了 LLM key 时，routes.ts 自动追加 LLM 综合解读：读取所有 QueryRun 的 evidenceCards 和 checks，产出诊断结论。

## 数据持久化

- Case 数据：`data/cases/:caseId/case.json`（JSON 文件）
- 内存缓存：`Map<string, CaseGraph>` 缓存最近加载的 graph
- Agent 临时文件：`PCAPAI_CASE_GRAPH_PATH` 指向的 temp JSON 文件
- LLM profiles：`.env` 中 `PCAPAI_LLM_PROFILE_*` 条目
- Learned patterns：`data/learned_patterns.json`（regex→adapterId 对，由 LLM 生成）

## Agent 边界

Leader Agent 通过 case-graph MCP 读取 case graph，通过 tshark-query MCP 查询原始包数据。Agent 不自行解析 pcap 文件，不执行 shell；真正的 tshark 调用发生在 `tshark-query` MCP 内。`case-graph` MCP 中除 `update_network_topology` 会写临时快照外，其余工具按只读证据访问使用。

如果没有 QueryRun 或没有选中通讯对，Agent 必须追问查询条件，不能给确定断点结论。

综合解读类问题：Agent 必须通过 `get_query_runs` 和 `get_evidence_cards` 读取 QueryRun 里的 evidenceCards、checks 和 protocolCorrelations，不能只看 case graph 顶层 packets/evidence/findings。

## 置信度策略

| 级别 | 含义 |
|------|------|
| `certain` | 确定性管线产出，多个 packet 事实支撑 |
| `high` | 多个事实或明确 mapping hint 支撑，没有明显反证 |
| `low` | 缺少关键上下文或只有单侧证据 |
| `needs_context` | 缺接口方向、节点角色、时间窗口等，不能给确定结论 |

没有证据时不输出确定结论。缺失观察必须标明覆盖范围和前提。

## 当前限制

- 上传 pcap 不全量解析 rawPackets，只有 QueryRun 按 display filter 读取有限样本
- NAT/LB 自动推断依赖启发式检测（TTL 差异、端口模式、ISN 跳跃），不保证覆盖所有场景；MappingHint 仍需手工录入
- L7 代理/SSL 卸载检测基于 HTTP 头（Via/XFF）和连接时序模式，多跳代理链路还原依赖 MappingHint
- 单 pcap 只返回单节点 hop，不伪造多跳
- Wireshark 采用本地桌面打开方式，不嵌入浏览器
- LLM 综合解读质量取决于模型遵循指令的能力，可能需要迭代调整 agent 指令
- Learned patterns 由 LLM 生成，质量取决于模型 regex 生成能力
- Insight engine 不做阈值过滤，报告量可能较大，需要 UI 侧筛选
