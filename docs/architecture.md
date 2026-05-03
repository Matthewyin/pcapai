# pcapAI 架构

## 架构概览

pcapAI 是 Agent-first 本地浏览器工作台，用于离线分析网络故障。核心流程：用户上传 pcap 并提问 → Chain Planner 规划分析链 → 确定性 protocol adapter 运行 tshark 产出证据 → Agent 综合解读证据链 → 输出诊断结论。

Protocol adapter 路由采用三层 fallback：硬编码 regex → 学习到的 pattern → agent（带 tshark-query MCP）。学习到的 pattern 由 LLM 动态生成并持久化到 `data/learned_patterns.json`。

```mermaid
flowchart LR
  Web["聊天工作台"] --> API["apps/api"]
  API --> Query["tshark-query MCP"]
  API --> Opener["evidence-opener MCP"]
  Query --> Tshark["tshark"]
  Opener --> Wireshark["本地 Wireshark"]
  API --> Planner["Chain Planner"]
  Planner --> Adapters["Protocol Adapters"]
  Planner --> Agent["Leader Agent"]
  Adapters --> Graph["case graph"]
  Agent --> CaseGraph["case-graph MCP"]
  Agent --> Query
  CaseGraph --> Graph
  Web --> SSE["SSE 流式输出"]
```

## 三层处理管线

```
用户问题
  ↓
Chain Planner (LLM 或本地兜底)
  ↓ 输出 AnalysisChainPlan (planKind: single | chain)
  ↓
┌─────────────────────────────────────────┐
│ 确定性层 (protocol adapters)             │
│ TCP / DNS / TLS / HTTP / ICMP / UDP     │
│ 三层路由：                               │
│   1. hardcoded regex match              │
│   2. learned patterns (JSON 文件)       │
│   3. agent fallback + 学习              │
│ 直接运行 tshark，产出 evidenceCards     │
│ + checks + protocolCorrelations         │
└─────────────────────────────────────────┘
  ↓ 多步链: executeChain + graph reload
  ↓
┌─────────────────────────────────────────┐
│ 综合解读层 (LLM agent)                   │
│ llm_explain intent → Leader Agent       │
│ 或自动综合 (无 llm_explain 步骤时追加)   │
│ 通过 case-graph MCP 只读 case graph     │
│ 通过 tshark-query MCP 查询原始包数据    │
│ 产出诊断结论 + suggestedQueries         │
└─────────────────────────────────────────┘
```

## 组件

### `apps/api` — Express API + Agent runtime

#### HTTP 层 (`src/http/`)
- **routes.ts** — REST 端点 + SSE 流式 agent 回答。Chain 执行流程：
  1. `planChain()` 规划分析链
  2. `executeChain()` 逐步执行，每步后 `reloadGraph()` 刷新 case graph
  3. 无 `llm_explain` 步骤时自动追加 LLM 综合解读
- **caseStore.ts** — case 持久化：`data/cases/:caseId/case.json`
- **capturePreprocess.ts** — 通过 `editcap -s` 裁剪 payload
- **reportBuilder.ts** — 从 case graph 生成结构化 Markdown 报告
- **llmSettings.ts** — LLM 配置文件管理（`.env` 中 `PCAPAI_LLM_PROFILE_*`）

#### Agent 层 (`src/agents/`)
- **runtime.ts** — OpenAI Agents SDK runtime：
  - `runChainPlanner()` — 规划分析链，输出 `AnalysisChainPlan`
  - `runIntentPlanner()` — 单步意图分类（无 LLM 时的兜底）
  - `runPcapTroubleshootingAgent()` — Leader Agent + 5 个 handoff subagent：
    - **TriageAgent** — 问题分流，决定交由哪个专业 subagent
    - **EvidenceAgent** — 综合解读证据链，读取 QueryRun evidenceCards 和 checks
    - **PathAgent** — 多节点路径分析和跨链路关联
    - **ProtocolAgent** — 协议级行为分析，可直接调用 tshark-query MCP 查询原始包数据
    - **ReportAgent** — 生成结构化诊断报告
  - 所有 agent 同时使用 case-graph MCP 和 tshark-query MCP
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
- **http.ts** — HTTP 事务（4xx/5xx），请求/响应匹配，多 check 输出
- **icmp.ts** — ICMP Unreachable/TTL Exceeded/Fragmentation
- **udp.ts** — UDP 流聚合
- 共享逻辑在 `builders.ts`：packet pair 分组、evidence card 创建、L7→TCP protocol correlations（DNS→TCP、TLS SNI→TCP、HTTP Host→TCP）
- `types.ts` 中 `runProtocolAdapter()` 实现三层路由：hardcoded regex → learned patterns → null（由调用方 fallback 到 agent）

### `apps/web` — React 工作台

单文件 React 19 应用（`src/main.tsx`）。聊天优先布局：
- 会话历史、消息流、底部输入框
- pcap 上传（文件选择 / 拖放 / 粘贴）
- Markdown 渲染（`marked` + `dompurify`）用于已完成的 assistant 消息
- 证据卡片在浏览器新标签页展示（Blob URL，"查看证据详情" 按钮）——聊天气泡保留文字分析，链接页用于 Wireshark 操作
- SSE 流式 agent 回答
- 链式步骤进度（chain_start → step_start → step_done → chain_done）
- Mapping hint / time offset hint 编辑
- LLM 设置管理（profile CRUD + 连通性测试）
- 深色/浅色主题切换
- 报告导出

### `packages/shared` — 共享 schema (`@pcapai/shared`)

Zod schema + TypeScript 类型，定义完整领域模型：
- `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`
- `PacketSummary`, `Conversation`
- `QueryRun`, `QueryPath`, `EvidenceCard`
- `ProtocolCorrelation`, `AccessCandidateGroup`
- `AnalysisChainPlan`, `AnalysisChainStep`, `ChainStepResult`
- `AgentAnswer`（含 `protocolCorrelations` 字段）, `QueryDiagnosis`
- `CaseGraph` — 聚合所有上述数据

### `config/defaults.json` — 集中配置

所有运行时默认值：API host/port（默认 `30022`）、CORS、MCP 启动命令、LLM 设置（默认 Doubao/ByteDance Ark）、tshark 配置、查询限制、诊断阈值。所有值可通过 `PCAPAI_*` 环境变量覆盖。

### MCP 服务器

三个基于 stdio 的 MCP 服务器（`@modelcontextprotocol/sdk`）：

#### `mcp/tshark-query` — tshark 查询引擎
15 个工具：`build_display_filter`、`get_capture_time_range`、`list_protocols`、`get_network_statistics`、`list_tcp_conversations`、`query_packets`、`list_tcp_resets`、`list_tcp_retransmissions`、`list_tcp_zero_window`、`list_icmp_events`、`list_dns_packets`、`list_udp_packets`、`list_tls_packets`、`list_http_packets`、`get_conversation_packets`

#### `mcp/evidence-opener` — Wireshark 打开器
用 pcap 路径 + display filter 打开本地 Wireshark。不分析数据包。

#### `mcp/case-graph` — Agent 只读工具层
16 个工具，Agent 通过这些工具只读 case graph：
- `load_case_graph` — 读取 case graph 摘要
- `get_case_statistics` — 确定性统计（TCP 通信对、诊断标签、时间范围）
- `get_query_runs` — 读取所有 QueryRun 列表
- `get_query_run` — 按 ID 读取单个 QueryRun
- `get_active_query_run` — 读取当前激活的 QueryRun
- `get_conversation` — 按 ID 读取通讯对
- `get_query_diagnosis` — 读取 selectedDiagnosis（checks、findings、nextSteps）
- `get_path_diagnosis` — 读取 PathHop、PathEdge 和边判断
- `get_protocol_correlations` — 读取 DNS/TLS/HTTP→TCP 关联
- `get_evidence_cards` — 读取证据卡片
- `get_finding` — 按 ID 读取判断结果
- `get_evidence` — 按 ID 读取证据事件
- `get_session_link` — 按 ID 读取跨节点会话关联
- `get_packet_detail` — 按 ID 读取数据包详情
- `explain_path` — 读取当前 QueryRun 通讯路径 hop
- `suggest_next_query` — 基于证据模式返回最多 5 个建议后续查询
- `export_report` — 导出 Markdown 报告草稿

## 查询管线

### Agent 查询（`POST /api/cases/:caseId/agent`）

```
用户问题
  ↓
1. Chain Planner 分类 → AnalysisChainPlan
  ↓
2a. Chain path (planKind=chain):
    executeChain → 逐步执行
    每步后 reloadGraph 刷新 case graph
    支持 paramsFrom 参数绑定
    无 llm_explain 步骤 → 自动追加 LLM 综合解读
  ↓
2b. Single deterministic path:
    protocol adapter 三层路由:
      hardcoded regex match → tshark 查询
      learned pattern match → tshark 查询
      无匹配 → agent fallback (case-graph + tshark-query MCP)
    → evidenceCards + checks + protocolCorrelations
    → 写入 QueryRun
  ↓
2c. Agent path (llm_explain intent):
    Leader Agent → handoff → subagent
    → 通过 case-graph MCP + tshark-query MCP
    → 诊断结论 + suggestedQueries
```

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

Leader Agent 通过 case-graph MCP 只读 case graph，通过 tshark-query MCP 查询原始包数据。Agent 不自行解析 pcap 文件，不执行 shell。

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
- NAT/LB 自动推断暂不强做，先依赖节点顺序和手工线索
- 单 pcap 只返回单节点 hop，不伪造多跳
- Wireshark 采用本地桌面打开方式，不嵌入浏览器
- LLM 综合解读质量取决于模型遵循指令的能力，可能需要迭代调整 agent 指令
- Learned patterns 由 LLM 生成，质量取决于模型 regex 生成能力
