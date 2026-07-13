# pcapAI 全量方案(Roadmap v2)

> 历史设计稿：主要目标已经实现，文中的待审状态、旧工具名和实施步骤不代表当前行为。当前架构以 [`architecture.md`](architecture.md) 和根目录 [`AGENTS.md`](../AGENTS.md) 为准。
>
> 状态:设计完成,待审。审完按阶段实现,每阶段独立验证。
> 关联:`docs/design-field-notes.md`(实战库 v0,已实现)、`docs/design-field-notes-roadmap.md`(旧版,本文替代)、`apps/api/src/agents/runtime.ts`(现有 Agent)

---

## 0. 这次方案相比上一版的根本变化

上一版把"实战知识库 + Agent 重构"当成两条线。这一版基于你的澄清,确立了**三层知识体系**,这是整个产品的骨架:

```
┌──────────────────────────────────────────────────────────┐
│ Skills 层(方法论):"怎么操作"——可复用的排障 SOP          │
│   例:"对比两端 SYN 包的 TCP options"                      │
│   特征:抽象、可被多个案例复用、偏操作步骤                 │
└──────────────────────────────────────────────────────────┘
              ↑ 引用(案例指定用哪些方法)
┌──────────────────────────────────────────────────────────┐
│ 实战知识库层(案例):"这个现象是什么"——具体案例的真因+RFC │
│   例:"SYN 无 SYN-ACK → 可能是 timestamp 不匹配(RFC7323)" │
│   特征:具体、带 RFC 依据、可被飞轮沉淀                    │
└──────────────────────────────────────────────────────────┘
              ↑ 验证(案例结论靠包数据支撑)
┌──────────────────────────────────────────────────────────┐
│ 抓包事实层(数据):"看到了什么"——原始包(tshark MCP)     │
└──────────────────────────────────────────────────────────┘
```

**timestamp 例子完整链路**:
- 抓包层:看到 SYN,没看到 SYN-ACK
- 实战库层:命中"SYN 无 SYN-ACK → 可能 timestamp 不匹配(RFC 7323§3.2)"
- Skills 层:执行"对比两端 TCP options"这个 SOP → 确认 timestamp 不匹配 → 下结论

**三者缺一不可**:只有实战库,Agent 知道"可能是什么"但不会验证;只有 Skills,Agent 会操作但不知道何时用;抓包层是两者的素材。

---

## 1. SDK 能力盘点(已调研,不造轮子)

| 能力 | SDK 原生支持 | 项目现状 | 方案 |
|---|---|---|---|
| **结构化输出** | ✅ `outputSchema`(Zod) | ❌ 手写 JSON 解析(100 行) | A1:替换为 outputSchema |
| **Session/记忆** | ✅ `Session` 接口 + `MemorySession` | ❌ 手动拼 chatHistory | A6:用 Session 管理跨轮 |
| **上下文压缩** | ✅ `OpenAIResponsesCompactionSession` | ❌ slice 截断 | A6:用压缩 Session |
| **dynamic instructions** | ✅ 函数接收 RunContext | 部分(prompt 拼字符串) | A3/A5:动态注入候选 |
| **handoff 多 agent** | ✅ 已在用 | ✅ leader+3 专家 | 保留 |
| **MCP 工具** | ✅ `mcpServers` | ✅ tshark-query/evidence-opener | 保留 |
| **function tools** | ✅ `tool()` | ✅ caseGraphTools | 扩展 |
| **guardrails** | ✅ 输入/输出校验 | ❌ 未用 | A5:根因结论必须挂 RFC(可选 guardrail) |
| **tracing** | ✅ `withTrace` | ✅ 已在用 | 保留 |
| **Skills** | ❌ 无原生(社区 issue #2361 在请求) | ❌ 无 | A7:自实现,借鉴 Claude skills 格式 |

**结论**:Sessions、outputSchema、Compaction 都是 SDK 已有能力,**直接用,不造轮子**。只有 Skills 要自己实现(格式借鉴 Claude skills)。

---

## 2. 各模块详细设计

### A1:outputSchema 替换手写 JSON 解析

**现状**:`runtime.ts` 的 `jsonOutputInstruction`(50行)+ `parseAgentOutput`/`firstJsonObject`/`formatAgentAnswer`(100行)手写 JSON 提取容错。

**改造**:
- 用 shared 的 `AgentAnswerSchema`(已存在 Zod)作 `outputSchema`
- Agent 构造传 `outputSchema: AgentAnswerSchema`
- 删掉手写解析,SDK 保证 `finalOutput` 合规

**风险**:MiniMax 对 structured output 支持**不确定**。**实测优先**:
- 实测通过 → 直接用
- 实测失败 → 保留手写 fallback,但用 `runAgentCompatibilityCheck` 同款探针检测后切换

**改造点**:`runtime.ts`(瘦100行)、新增 `outputSchemaProbe.ts`(兼容性探针)

**不做**:不自己写 JSON 解析器

### A2:Agent 成为第一入口(激进,你已同意)

**现状**:用户问题 → chain planner(12 intent)→ adapter 拦路 → Agent 兜底

**改造**(激进):
- **删** chain planner 自动路由(`runChainPlanner` 调用)
- **删** learned pattern 自动拦截(`tryLearnedBypass`)
- **删** 29 insight analyzer 的 prompt 预注入(`hypothesisKnowledge` 改为 Agent 按需调 `get_insights`)
- 保留 planner/adapter **代码**(专家直达通道 + Agent 工具),只删"拦路调用"
- `AgentRuntimeService.run` 直接进 `runPcapTroubleshootingAgent`

**改造点**:`agentRuntimeService.ts`、`plannerService.ts`、`runtime.ts`(删 hypothesisKnowledge 注入)

**保留**:`/api/query-runs` 确定性 API、前端快捷按钮(专家直达)

### A3:实战库强制接入 + 精确命中

**现状**:v0 注册了 `search_field_notes`,Agent 可能不调;timestamp 弱命中

**改造**:
- Leader instructions 强制:"开始推理前必须调 search_field_notes"
- `extractPacketFeatures` 提取 `missingFlags`(复用 MCP 的 handshakePhase):
  - `handshakePhase==="syn"` → `missingFlags:["SYN-ACK"]`
  - timestamp 种子靠 missingFlags 精确命中(+3 分)
- FTS5 question 兜底(特征分=0 时):复用 `buildFtsMatchQuery`

**改造点**:`fieldNotesService.ts`、`buildFieldNotesIndex.ts`(加 FTS5 虚拟表)、`runtime.ts`(prompt)

### A4:RFC 工具接入 Agent(防幻觉边界)

**改造**:
- 注册 `search_rfc`/`get_rfc_section` 到 caseGraphTools
- Leader 强制:"根因结论必须经 get_rfc_section 回读 RFC,引用带编号+§section;无 RFC 依据标'经验推测'"
- HypothesisAgent 已有这条规则(`runtime.ts:538`),Leader 补上

**改造点**:`caseGraphTools.ts`、`runtime.ts`

### A5:结论分层结构化输出

**改造**:
- AgentAnswer 加 `rootCauses: Array<{cause, rfcRef?, rfcDocId?, rfcSection?, confidence, verified, evidencePacketIds[]}>`
- prompt 要求分层:事实(抓包证据)→ 模式(统计)→ 根因(RFC 或标推测)→ 建议(依赖根因)
- UI:无 RFC 引用的根因标黄"经验推测"
- 可选 guardrail:输出校验"根因要么有 rfcRef 要么标推测",否则拒绝

**改造点**:`packages/shared`(AgentAnswerSchema)、`runtime.ts`、`apps/web`

### A6:Session + 上下文压缩(你重点要求)

**现状**:手动拼 `chatHistory`(slice 截断)、工具输出 `slice(-8)` 硬截断

**改造**:
- 实现 `SqliteSession implements Session`(5 个方法,存 case 目录)
- `Runner.run(agent, input, { session })` —— SDK 自动管理跨轮
- **压缩策略**(三层,你已同意):
  1. SDK 原生:`OpenAIResponsesCompactionSession` 包裹(自动压缩历史)—— 若 MiniMax 不支持 responses.compact,降级
  2. 应用层:每轮结束用小模型把工具输出摘要成 1-2 句,存 session(新工具 `summarize_tool_output`)
  3. 截断:兜底(`MemorySession` 的 getItems limit)

**官方能力**:`Session` 接口 + `MemorySession` + `OpenAIResponsesCompactionSession`

**改造点**:新增 `sqliteSession.ts`、`runtime.ts`(接入 session + 摘要)、`config`(session 配置)

**不做**:不用 mem-0(实战库已覆盖沉淀);不自己写压缩算法(用 SDK 原生)

### A7:Skills 组件(核心创新,你重点要求)

**这是没有 SDK 原生支持的,要自己实现,但格式借鉴 Claude skills。**

#### 7.1 Skills 的本质

Skill = **markdown 格式的可复用排障 SOP**。它是"方法论层",比实战库更抽象。

对比:
- 实战库条目:"SYN 无 SYN-ACK → timestamp 不匹配"(具体案例)
- Skill:"如何对比两端 TCP options 验证 timestamp 不匹配"(操作方法)

一个 Skill 可被多个实战库条目引用(多个案例共享同一验证方法)。

#### 7.2 Skill 文件格式(借鉴 Claude skills)

`data/skills/verify-tcp-options.md`:
```markdown
---
name: verify-tcp-options
description: 对比两端 TCP 包的 options 字段(如 timestamp、SACK、MSS),验证配置是否匹配
triggers:
  - "timestamp 不匹配"
  - "SYN 无 SYN-ACK 且需验证 options"
tools_required:
  - follow_tcp_stream
  - get_packet_detail
---

# 验证 TCP Options 匹配

## 适用场景
当怀疑连接建立失败与 TCP options 配置差异有关时使用。

## 执行步骤
1. 用 follow_tcp_stream 取出客户端侧 SYN 包
2. 用 get_packet_detail 查看该 SYN 的 TCP options(timestamp、SACK、MSS、WScale)
3. 同样取服务端侧 SYN-ACK(若有)的 options
4. 对比两端:
   - timestamp 是否都启用
   - MSS 是否一致
   - WScale 是否协商
5. 发现差异 → 对照 RFC 7323(或相关 RFC)确认是否违规

## 判定标准
- 任一端 timestamp 未启用而对端启用 → 可能导致 SYN 被丢弃(RFC 7323§3.2)
- MSS 不一致 → 协商取小值,非故障但影响性能
```

#### 7.3 实战库与 Skills 的关联

实战库条目加 `skillIds` 字段:
```json
{
  "id": "fn-tcp-timestamp-mismatch-001",
  "candidateCauses": [{
    "cause": "TCP timestamp option 不匹配",
    "skillIds": ["verify-tcp-options"]  ← 引用 Skill
  }]
}
```

Agent 检索实战库命中后,连带取出关联 Skills,按 SOP 执行。

#### 7.4 Skills 的检索

- **不**用复杂检索。Skill 数量少(初期手动写,几十个量级)
- Agent 工具 `list_skills` / `get_skill(name)` 直接读 markdown
- 实战库命中时自动关联(通过 skillIds),无需独立检索

#### 7.5 Skills 的创建(Agent 自我进化)

**这是你说的"Agent 有创建 skills 的 skills"。** 实现方式:

- 工具 `create_skill`:Agent 把"验证有效的操作流程"写成 markdown,存到 `data/skills/`
- **借鉴 Claude skills-creator 的格式和流程**(不能直接调用,因为运行时是 OpenAI SDK 不是 Claude Code):
  - 格式:frontmatter(name/description/triggers/tools_required)+ 正文步骤
  - 流程:Agent 观察到自己执行了一套有效步骤 → 调 create_skill 固化
- 初始用 Claude skills-creator **在开发期手动生成几个种子 skill**(我可以用 skills-creator 跑),然后 Agent 运行时复用这套格式自我扩展

**改造点**:
- 新增 `skillsService.ts`(读写 markdown,frontmatter 解析)
- `caseGraphTools.ts` 加 `list_skills`/`get_skill`/`create_skill` 三个工具
- 实战库 schema 加 `skillIds`
- 种子 skills(开发期用 Claude skills-creator 协助生成)

**不做**:
- 不做 Skill 的复杂语义检索(数量少,直接 list)
- 不做 Skill 版本管理(v1 先简单)
- 不自动从日志挖掘 Skill(显式 create_skill)

### A8:AGENTS.md + 系统提示词统一设计

**现状**:`AGENTS.md` 是给 Codex 的工程说明;运行时 Agent 的方法论散在 prompt 各处

**改造**:
- `AGENTS.md` 保留(给 Codex/开发),描述代码架构
- **新增** `docs/agent-methodology.md`:排障方法论(给运行时 Agent 读)
  - 诊断阶段模型(interview → hypothesis → testing → conclusion)
  - 何时用实战库 / Skills / RFC
  - 结论可信度标准
- Leader prompt 从 `agent-methodology.md` 加载(开发期可改,不改代码)

**改造点**:新增 `docs/agent-methodology.md`、`runtime.ts`(prompt 从文件加载)

---

## 3. 实施顺序(修订版,含 Skills/Session)

| 阶段 | 内容 | 依赖 | 验证标准 |
|---|---|---|---|
| **P0** | ✅ 实战库 v0(已完成) | — | timestamp 弱命中 ✅ |
| **P1** | RFC 工具接入 Agent(A4) | v0 | Agent 能调 search_rfc/get_rfc_section |
| **P2** | 实战库精确命中 + 强制接入(A3) | v0 | timestamp 靠 missingFlags 精确命中 |
| **P3** | Skills 基础设施(A7:服务+工具+种子) | v0 | Agent 能 list/get/create skill |
| **P4** | 实战库 ↔ Skills 关联 | P2,P3 | 命中实战库自动带出关联 Skill |
| **P5** | Session + 上下文压缩(A6) | 无 | SqliteSession 跨轮记忆 + 压缩生效 |
| **P6** | outputSchema + 结论分层(A1+A5) | 无 | MiniMax 兼容性验证 + rootCauses 分层 |
| **P7** | Agent 第一入口 + adapter 瘦身(A2) | P1-P6 | 用户问题直接进 Agent |
| **P8** | 沉淀闭环(UI 重设计 + verify/dispute + create_skill 完善) | P4,P7 | 用户确认写回 + Agent 自建 skill |
| **P9** | AGENTS.md + 方法论文档(A8) | 全部 | prompt 从文档加载 |

**顺序逻辑**:
- P1-P4 是"给 Agent 配弹药"(RFC + 实战库 + Skills)
- P5-P6 是"给 Agent 升级底层"(记忆 + 结构化输出)
- P7 是"让 Agent 上前线"(切流量,风险最高放这里)
- P8-P9 是"飞轮 + 文档化"(等跑通再打磨)

---

## 4. 待你确认的关键点

1. **Skills 格式(A7.2)**:用 markdown + frontmatter(借鉴 Claude skills),Agent 工具读写。认可吗?

2. **Skill 创建(A7.5)**:运行时 Agent 用 `create_skill` 工具自建(借鉴 Claude skills-creator 格式);开发期我用 Claude skills-creator 协助生成几个种子。认可吗?

3. **Session 实现(A6)**:自实现 `SqliteSession`(存 case 目录),用 SDK 原生压缩。认可吗?(不用 mem-0,你已确认)

4. **outputSchema 风险(A1/P6)**:MiniMax 可能不支持,要保留 fallback 探针。接受?还是 P6 暂缓?

5. **P8 UI 重设计**:你说"UI 界面需要重新设计"。这是 P8 的大头。你希望:
   - (a) P8 时我们专门讨论 UI 设计(推荐,UI 要单独想)
   - (b) 还是现在就先画 UI 草图?

6. **实施顺序**:认可 P1→P9 吗?特别确认 **P7(Agent 切流量)放第 7 位**,不提前。

7. **种子 Skills**:除了"verify-tcp-options",你脑子里还有哪些常用的排障 SOP?(越多越好,种子决定初始质量)

---

## 5. 诚实声明

这份方案我已经收敛到最小必要范围:
- SDK 有的能力(outputSchema/Session/Compaction/MCP/handoff)**全用原生,不造轮子**
- SDK 没有的(Skills)**借鉴成熟格式(Claude skills)自实现**,不发明新格式
- 不用 mem-0(实战库已覆盖沉淀)
- adapter 瘦身只删"拦路调用",不删代码(P7 保守降级,但你已同意激进——所以 P7 会删)

工作量仍然不小(9 个阶段)。如果你要压缩,**P1+P2+P3+P4 是最小可用集**(RFC + 实战库 + Skills + 关联),这四项跑通,"三层知识体系"就成立了。P5-P9 是增强。

你怎么定?确认后我从 P1 开始,每个 P 完成停下来验证。
