# 实战知识库(Field Notes)v0 设计文档

> 状态:v0 锁死范围,待实现
> 范围边界:本文档只描述 v0(最小可验证版本)。飞轮权重、沉淀闭环 UI、高级特征、CRUD、FTS5 question 兜底等 **全部不做**,留待 v0 验证后另起 roadmap 文档。

## 1. v0 要证明的一件事

**遇到"SYN 无 SYN-ACK"的 pcap,Agent 能因为知识库命中而快速给出 timestamp 结论并引用 RFC 7323。**

这一条跑通,就证明"Agent + 实战库 + RFC"三角成立,值得继续投入。

## 2. v0 范围(只做这些)

| 做 | 不做 |
|---|---|
| SQLite schema + 构建脚本 | 笔记 CRUD API |
| `fieldNotesService.ts`(纯特征检索) | FTS5 question 兜底检索 |
| `extractPacketFeatures`(flag 级) | 重传模式等高级特征 |
| `search_field_notes` Agent 工具 | 沉淀闭环 UI |
| 2 条种子数据 | 飞轮权重排序 |
| 检索打分测试 | verifiedCount/disputedCount 参与排序 |

## 3. 存储与技术栈

- **SQLite + FTS5**,与 RFC 库(`better-sqlite3`)一致
- 路径:`data/field-notes/field-notes.db`
- 种子源:`data/field-notes/seeds/*.json`(可 git 管理、可审查)
- 构建脚本:`apps/api/scripts/buildFieldNotesIndex.ts`
- 运行时:**只读** SQLite
- 配置:`config/defaults.json` 新增 `fieldNotes` 节

## 4. 数据模型(v0 精简 schema)

```sql
CREATE TABLE notes(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  protocols TEXT NOT NULL,           -- JSON array
  symptoms TEXT NOT NULL,            -- JSON array
  packet_features TEXT NOT NULL,     -- JSON object
  candidate_causes TEXT NOT NULL,    -- JSON array
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);
```

**v0 不建**:`verified_count`/`disputed_count`/`last_verified_at`(飞轮字段,无沉淀闭环前无意义)。这些字段加进来是死数据,等 v1 沉淀闭环时再加。

```typescript
type PacketFeatures = {
  observedFlags?: string[];   // ["SYN"]
  missingFlags?: string[];    // ["SYN-ACK"]
  analysisFlags?: string[];   // ["retransmission"]
  protocols?: string[];       // ["TCP"]
};

type CandidateCause = {
  cause: string;
  rfcDocId?: number;
  rfcSection?: string;
  likelihood: "high" | "medium" | "low";
  howToVerify: string;
};

type FieldNote = {
  id: string;
  title: string;
  summary: string;
  protocols: string[];
  symptoms: string[];
  packetFeatures: PacketFeatures;
  candidateCauses: CandidateCause[];
  source: "seed";
  createdAt: string;
};
```

## 5. 检索算法(v0 纯特征匹配)

```
输入:packetFeatures(从 case graph 提取)
  ↓
第 1 层:协议过滤
  packetFeatures.protocols ∩ note.protocols 非空
  ↓
第 2 层:特征打分(确定性)
  - missingFlags 完全命中: +3 分/个
  - observedFlags 命中:    +1 分/个
  - analysisFlags 命中:    +2 分/个
  特征分 > 0 才保留
  ↓
第 3 层:排序
  按特征分降序;同分按 id 升序(稳定)
  ↓
输出:top 3
```

**v0 不做**:question 文本参与、飞轮权重、FTS5 兜底。纯特征匹配,可解释、可测试。

## 6. Agent 接入(v0)

### 6.1 工具注册位置

`search_field_notes` 注册到 **caseGraphTools**(Agent 自主调用),不进 AgentToolRegistry(adapter 体系)。理由:这是知识查询,不是确定性 adapter。

### 6.2 工具行为

- 输入:无参数(从当前 case graph 提取特征)或可选 `question`
- 内部:`extractPacketFeatures(graph)` → `searchFieldNotes(features)`
- 输出:top 3 候选,每条含 `{title, summary, candidateCauses, featureScore}`

### 6.3 失败降级

库不存在/检索异常 → 工具返回空结果(不抛错),Agent 正常自主推理。知识库是增强,不是依赖。

### 6.4 Agent prompt 引导(v0 手动验证)

v0 不改 Agent 的系统 prompt 自动注入候选。先手动验证:用测试 pcap 跑,观察 Agent 是否主动调用 `search_field_notes`。如果 Agent 不知道调,再考虑在 prompt 里加引导(v0 范围内的微调)。

## 7. 种子数据(v0 恰好 2 条)

### 种子 1:TCP timestamp 不匹配

```json
{
  "id": "fn-tcp-timestamp-mismatch-001",
  "title": "TCP timestamp option 不匹配导致 SYN 无 SYN-ACK 响应",
  "summary": "客户端发出 SYN 但服务端不回 SYN-ACK,常见误判为防火墙拦截,实际可能是 TCP options 中的 timestamp 不匹配。",
  "protocols": ["TCP"],
  "symptoms": ["SYN 无 SYN-ACK", "握手失败", "连接建立失败"],
  "packetFeatures": {
    "observedFlags": ["SYN"],
    "missingFlags": ["SYN-ACK"],
    "protocols": ["TCP"]
  },
  "candidateCauses": [
    {
      "cause": "TCP timestamp option 不匹配",
      "rfcDocId": 7323,
      "rfcSection": "3.2",
      "likelihood": "medium",
      "howToVerify": "对比两端 SYN 包的 TCP options 是否都含 timestamp;检查 sysctl net.ipv4.tcp_timestamps"
    },
    {
      "cause": "防火墙/中间设备拦截",
      "likelihood": "medium",
      "howToVerify": "检查沿途设备是否有 SYN 丢弃策略;查看是否有 ICMP unreachable"
    }
  ],
  "source": "seed"
}
```

### 种子 2:TCP 指数退避重传

```json
{
  "id": "fn-tcp-retransmission-backoff-001",
  "title": "TCP 重传呈指数退避模式(200/400/800ms)",
  "summary": "TCP 重传间隔呈倍数增长(典型 200→400→800ms),是 RFC 6298 定义的标准退避行为,说明对端未 ACK 触发了 RTO 重传。",
  "protocols": ["TCP"],
  "symptoms": ["重传", "RTO 超时重传", "对端无响应"],
  "packetFeatures": {
    "observedFlags": ["SYN", "ACK", "PSH"],
    "analysisFlags": ["retransmission"],
    "protocols": ["TCP"]
  },
  "candidateCauses": [
    {
      "cause": "对端无响应触发 RTO 指数退避重传(RFC 6298)",
      "rfcDocId": 6298,
      "rfcSection": "2",
      "likelihood": "high",
      "howToVerify": "统计重传包时间间隔,验证是否呈 2 倍增长;检查对端是否回 ACK"
    }
  ],
  "source": "seed"
}
```

## 8. `extractPacketFeatures` 提取逻辑(v0)

从 case graph 的 packet samples 提取(v0 只做 flag 级,不做会话级时序):

```typescript
function extractPacketFeatures(graph: CaseGraph): PacketFeatures {
  const packets = graph.rawPackets ?? [];
  const protocols = new Set(packets.map(p => p.protocol.toUpperCase()).filter(Boolean));
  const observedFlags = new Set<string>();
  const analysisFlags = new Set<string>();
  for (const p of packets) {
    p.tcpFlags?.forEach(f => observedFlags.add(f));
    if (p.tcpAnalysis?.retransmission || p.tcpAnalysis?.fastRetransmission) analysisFlags.add("retransmission");
    if (p.tcpAnalysis?.zeroWindow) analysisFlags.add("zero_window");
  }
  return {
    observedFlags: [...observedFlags],
    analysisFlags: [...analysisFlags],
    protocols: [...protocols]
  };
}
```

**v0 不提取 missingFlags**(需要会话级时序判断,复杂)。timestamp 种子的 `missingFlags:["SYN-ACK"]` 在 v0 靠 `observedFlags:["SYN"]` + `protocols:["TCP"]` 部分命中(missingFlags 不参与打分,因为没有提取端)。

**这意味着 v0 对 timestamp 种子的命中是"弱命中"(只靠 observedFlags:SYN)。** 这是 v0 的已知简化,验证时关注:即使弱命中,Agent 是否仍能从候选中获得价值。

> 待 v0 验证后,如果 missingFlags 提取对命中质量关键,再在 v1 加入会话级提取(可复用 MCP 的 handshakePhase)。

## 9. 验证标准(v0 跑通的唯一判据)

1. `npm run fieldnotes:build` 生成 `data/field-notes/field-notes.db`,含 2 条种子
2. 用测试:构造 `packetFeatures = {observedFlags:["SYN"], protocols:["TCP"]}`,`searchFieldNotes` 返回 timestamp 种子(featureScore ≥ 1)
3. 单元测试覆盖:打分逻辑、协议过滤、topK 截断、空结果
4. `search_field_notes` 工具注册成功,Agent 运行时可调用(手动观察调用日志)

## 10. v0 不解决的已知问题(明确列出,避免误以为是 bug)

- timestamp 种子靠 SYN 弱命中,可能误命中其他只有 SYN 的场景
- 没有沉淀闭环,种子永远是 2 条
- missingFlags 不提取,失去精确匹配能力
- Agent 可能不会主动调工具(需要 prompt 引导,但 prompt 调整不在 v0 范围)

这些问题等 v0 验证三角成立后,在 roadmap 里逐条解决。
