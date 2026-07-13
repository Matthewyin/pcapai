# 实战知识库 + Agent 重构 全量方案(Roadmap)

> 历史设计稿：用于保留演进过程，不代表当前运行链路。当前架构以 [`architecture.md`](architecture.md) 和根目录 [`AGENTS.md`](../AGENTS.md) 为准。
>
> 状态:设计完成,待你确认后分阶段实现
> 关联:`docs/design-field-notes.md`(v0 已实现)、`apps/api/src/agents/runtime.ts`(现有 Agent)

本文档覆盖 v0 之后的**全部功能**,目标是把 pcapAI 从"adapter 主导、Agent 兜底"重构为"Agent 第一入口、实战知识库做先验、RFC 做边界"。

每一项都标注了:
- **官方 SDK 能力**:优先用 `@openai/agents` 原生,不重复造轮子
- **改造点**:具体动哪些文件
- **不做**:明确边界,防止跑偏

---

## 总体架构(目标态)

```
用户上传 pcap + 问一句话
    ↓
┌─ Leader Agent(唯一大脑)─────────────────────────────────┐
│                                                           │
│  [强制第一步] search_field_notes                          │
│     ← 实战知识库先验(命中=候选真因+RFC 引用)             │
│                                                           │
│  Agent 自主推理(无 chain planner 拦路):                  │
│     1. 提取症状(基于抓包特征,确定性)                     │
│     2. 对照候选 → 形成假设                                  │
│     3. tshark MCP 取证据                                   │
│     4. 跨文件关联(B,mapping hints)                        │
│     5. RFC 验证根因(search_rfc / get_rfc_section)         │
│     6. 结构化输出(outputSchema,分层:事实/模式/根因/建议) │
│        根因结论必须挂 RFC 引用或标注"推测"                 │
│                                                           │
│  [handoff] Hypothesis/Path/Protocol 专家(按需)           │
└───────────────────────────────────────────────────────────┘
    ↓ 工具箱(Agent 按需调用,不是拦路):
    - tshark MCP(取数,已有)
    - search_field_notes(实战先验,v0 已做)
    - search_rfc / get_rfc_section(RFC 验证,已有但未接 Agent)
    - 精简版 pcapai_ 工具(高频确定性动作)
    - 沉淀工具 record_field_note(P2,飞轮)
```

---

## 实战知识库演进(v0 → v1 → v2)

### v1:提升命中质量 + Agent 强制接入

**问题**:v0 的 timestamp 种子靠 `observedFlags:SYN` 弱命中,任何含 SYN 的场景都命中,误报多。

**改造**:

1. **提取 missingFlags**(复用方案 B 成果)
   - MCP 已有 `handshakePhase`,在 `extractPacketFeatures` 里读取 conversations
   - `handshakePhase==="syn"` → `missingFlags:["SYN-ACK"]`
   - 这样 timestamp 种子能靠 `missingFlags` 精确命中(+3 分),不再弱命中

2. **FTS5 question 兜底检索**
   - schema 加 `notes_fts` 虚拟表(已在 v0 预留,构建脚本补充)
   - 特征分=0 时,用 `buildFtsMatchQuery(question)` 走 FTS5 关键词检索
   - 复用 `rfcCorpus.ts` 的 `buildFtsMatchQuery`(不造新轮子)

3. **飞轮字段 + 权重排序**
   - schema 加 `verified_count`/`disputed_count`/`last_verified_at`
   - 排序公式:`finalScore = featureScore × (1 + verifiedCount×0.1) / (1 + disputedCount×0.5)`

**官方 SDK 能力**:无(纯后端检索逻辑)

**改造点**:`fieldNotesService.ts`、`buildFieldNotesIndex.ts`

**不做**:不引入 embedding 语义检索(bm25+特征够用,embedding 要重建索引,过度)

### v2:沉淀闭环(飞轮启动)

**问题**:种子永远是 2 条,无法积累。

**改造**:

1. **`record_field_note` Agent 工具**(注册到 caseGraphTools)
   - Agent 排障结束后主动调用,把"现象→真因→RFC"沉淀
   - 写入 `notes` 表(运行时可写,需开放 SQLite 写连接)

2. **用户确认/纠正 API**(HTTP 路由)
   - `POST /api/field-notes/:id/verify` —— confirmed → verifiedCount++
   - `POST /api/field-notes/:id/dispute` —— disputedCount++,body 带纠正后的 cause
   - `POST /api/field-notes` —— 手动新增(专家用户/管理员)

3. **前端 UI**
   - Agent 结论后显示"这个结论对吗? [✓ 正确] [✗ 不对,实际是...]"
   - 点击触发 verify/dispute API

**官方 SDK 能力**:用 Agent 的 `function tool` 实现沉淀(已验证 caseGraphTools 模式可行)

**改造点**:`caseGraphTools.ts`(加工具)、`routes.ts`(加 API)、`fieldNotesService.ts`(加写方法)、`apps/web`(加 UI)

**不做**:不做自动学习(从对话日志挖掘),v2 先做显式人工确认

---

## Agent 重构(核心,改动最大)

### A1:用 `outputSchema` 替换手写 JSON 解析(去重复造轮子)

**现状**:`runtime.ts` 用 `jsonOutputInstruction`(50 行 prompt)+ `parseAgentOutput`(手写 JSON 提取 + `<think>` 剥离 + 容错)—— 这是 SDK `outputSchema` 要解决的。

**改造**:
- 定义 `AgentAnswerSchema`(用 shared 里已有的 Zod schema)
- Leader/专家 Agent 构造时传 `outputSchema: AgentAnswerSchema`
- 删掉 `jsonOutputInstruction`、`parseAgentOutput`、`firstJsonObject`、`formatAgentAnswer` 等手写解析
- SDK 自动保证 `finalOutput` 符合 schema,无需容错解析

**官方 SDK 能力**:`Agent({ outputSchema })` + Zod(项目已用 Zod)

**改造点**:`runtime.ts`(瘦身约 100 行)、`packages/shared`(确认 AgentAnswerSchema 完整)

**风险**:部分第三方模型(非 OpenAI)对 `outputSchema`(底层是 JSON Schema/structured output)支持不一。MiniMax 需验证。**验证不通过则保留 fallback,不强推。**

**不做**:不自己写 JSON 解析器(SDK 已经做)

### A2:Agent 成为第一入口(砍拦路逻辑)

**现状**:用户问题先进 `runChainPlanner` → 12 intent 拆分 → 命中 adapter 就绕过 Agent → 没命中才 Agent。

**改造**:
- `AgentRuntimeService.run` 改为**直接调 `runPcapTroubleshootingAgent`**
- chain planner 降级为**可选**(LLM 未配置时用本地 fallback,或作为 Agent 的内部工具保留)
- 砍掉 `patternLearner` 的自动路由拦截(learnedBypass)

**官方 SDK 能力**:无(架构调整)

**改造点**:`agentRuntimeService.ts`、`plannerService.ts`

**不做**:**不删** chain planner 和 adapter 代码(破坏性太大,先让 Agent 绕过它们,后续评估是否删)

### A3:`search_field_notes` 强制接入(prompt 引导)

**现状**:v0 注册了工具,但 Agent 可能不主动调。

**改造**:在 Leader Agent 的 instructions 里加强制规则:
```
## 第一步(强制)
开始任何推理前,必须先调用 search_field_notes。
- 命中:优先验证候选真因,验证通过引用对应 RFC 下结论
- 不命中:基于症状自主推理
```

**官方 SDK 能力**:无(prompt 工程)

**改造点**:`runtime.ts`(Leader instructions)

**不做**:不用 guardrails 强制(guardrails 是校验,不是流程控制;prompt 引导够用且更灵活)

### A4:RFC 工具接入 Agent(防幻觉边界)

**现状**:`searchRfc`/`getRfcSection` 只在 HTTP 路由,Agent 用不了。

**改造**:
- 注册 `search_rfc`、`get_rfc_section` 到 caseGraphTools(对齐现有工具风格)
- Leader instructions 强制:"根因结论必须经 get_rfc_section 回读 RFC 原文,引用带编号和 §section;无 RFC 依据的结论必须标注'经验推测'"
- 这条 HypothesisAgent 的 instructions 已有(`runtime.ts:538`),Leader 也要补

**官方 SDK 能力**:无(工具注册 + prompt)

**改造点**:`caseGraphTools.ts`、`runtime.ts`

### A5:结论分层(防幻觉的结构化输出)

**现状**:AgentAnswer 没有"事实/模式/根因/建议"的明确分层。

**改造**:
- AgentAnswer 加字段:`rootCauses: Array<{cause, rfcRef?, confidence, verified}>`
- prompt 要求:事实(抓包证据)、模式(统计)、根因(必须 RFC 或标注推测)、建议(依赖根因)分层输出
- UI 渲染时,无 RFC 引用的根因标黄"经验推测"

**官方 SDK 能力**:`outputSchema`(配合 A1)

**改造点**:`packages/shared`(AgentAnswerSchema 加字段)、`runtime.ts`(prompt)、`apps/web`(UI 渲染)

---

## adapter 瘦身(P1,破坏性)

**原则**:adapter 退化为 Agent 工具箱,不拦路。但要保留专家用户的直达通道。

**改造**:

1. **保留为 Agent 工具**(高频 + 确定性价值):
   - 列 RST/重传/零窗口/单向连接
   - 跨文件 TCP 会话关联(B 核心)
   - follow TCP stream
   - expert info 汇总

2. **砍掉或降级**(在跟 Wireshark 抢活 / 替 Agent 思考):
   - chain planner 12 intent 自动拆分 → 降级为可选(A2)
   - learned pattern 自动路由 → 停用拦截
   - 29 个 insight analyzer 预扫 → **保留但不再预扫注入** prompt,改为 Agent 按需调 `get_insights`
   - TCP 健康全景六维分类 → 保留工具,但不再做"精确判定每条连接"(止血版已降级)

3. **专家直达通道**(回应"两者都要"):
   - 保留 `/api/cases/:caseId/query-runs` 等确定性 API
   - 前端可加快捷按钮(如"列出所有 RST"),直接走 adapter,不经过 Agent

**官方 SDK 能力**:无

**改造点**:`agentRuntimeService.ts`、`plannerService.ts`、`insightEngine.ts` 调用处、`apps/web`

**不做**:不删现有 adapter 代码(先绕过,稳定后再评估删除)

---

## 实施顺序(分阶段,每阶段可独立验证)

| 阶段 | 内容 | 依赖 | 验证标准 |
|---|---|---|---|
| **P0** | v0 已完成(实战库种子 + 特征检索) | — | SYN 场景弱命中 timestamp ✅ |
| **P1** | RFC 工具接入 Agent(A4) | v0 | Agent 能调 search_rfc/get_rfc_section |
| **P2** | search_field_notes 强制接入(A3) | v0 | Agent 第一步主动调实战库 |
| **P3** | 实战库 v1(精确命中 + 飞轮字段)(v1) | v0 | timestamp 靠 missingFlags 精确命中 |
| **P4** | outputSchema 替换手写解析(A1) | 无 | MiniMax 支持 outputSchema 验证通过 |
| **P5** | 结论分层(A5) | P4 | AgentAnswer 输出 rootCauses 分层 |
| **P6** | Agent 第一入口(A2)+ adapter 瘦身 | P1-P5 | 用户问题直接进 Agent,不经 planner |
| **P7** | 沉淀闭环 v2(工具+API+UI) | P3 | 用户确认能写回知识库 |

**关键依赖关系**:
- P4(outputSchema)是 P5(结论分层)的前置 —— 分层要靠结构化输出落地
- P6(Agent 第一入口)放后面 —— 等前面能力就绪再切流量,降低风险
- P7(沉淀闭环)最后 —— 飞轮要等前面能力跑通才有意义

---

## 待你确认的关键决策

1. **P4 outputSchema 的风险接受度**:MiniMax 对 structured output 支持不确定,验证失败要保留 fallback。接受这个风险吗?还是 P4 暂缓,先做不依赖它的部分?

2. **P6 adapter 瘦身的力度**:
   - (a) 激进:删 chain planner、learned pattern、insight 预扫
   - (b) 保守:只让 Agent 绕过,代码保留(我倾向 b,降低风险)

3. **P7 沉淀闭环的范围**:
   - 要不要做前端 UI?还是先只做 API + Agent 工具,UI 后补?

4. **实施顺序**:认可 P1→P7 的顺序吗?还是你有优先级调整?(比如先把 Agent 改成第一入口 P6 提前?)

确认后我从 P1 开始实现。每个 P 完成后我会停下来让你验证,不连续做完。
