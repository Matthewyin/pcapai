# pcapAI 产品设计

## 目标

pcapAI 是本地抓包排障工作台。用户上传 pcap 后直接与 Leader Agent 对话；Agent 从确定性工具获取包事实，结合 Skills、Field Notes 和 RFC 原文给出可回溯结论。

## 主链

```text
上传 pcap + 用户问题
  → Leader Agent
  → Skills / Field Notes 提供方法与案例先验
  → pcapai_ 工具或 tshark-query MCP 提取包事实
  → get_rfc_section 回读规范原文
  → 运行时核验 RFC 章节与证据包 ID
  → 结论、证据卡、后续查询与 Wireshark 入口
```

Chain Planner、TCP/DNS/TLS/HTTP/ICMP/UDP adapters 和 approved learned patterns 保留为 Agent 工具或专家直达通道，不在聊天入口前拦截问题。

## 能力范围

- TCP：握手、RST、重传、Zero Window、单向流、连接健康矩阵、窗口与时序异常。
- DNS、TLS、HTTP、ICMP、UDP、QUIC、NTP、SSH 协议异常。
- DNS → TCP → TLS → HTTP 跨协议时序和多节点路径关联。
- L7 代理、SSL 卸载和 NAT 启发式识别。
- TCP stream 查看、证据卡、Wireshark 跳转、Markdown 报告。
- Leader Agent 与 Hypothesis、Path、Protocol 三个专家 Agent 协作。

系统不做实时抓包、自研 pcap decoder，也不允许 Agent 直接执行 shell 或猜测包事实。

## 知识与证据边界

知识分为三层：

1. Skills：可复用排障 SOP。
2. Field Notes：现象、候选原因、验证方法和 RFC 线索。
3. Packet facts：tshark 从当前抓包提取的确定性事实。

RFC 是规范边界。模型输出的 `rfcVerified=true` 只有在本轮真实读取匹配章节、且所有 `evidencePacketIds` 均来自当前 CaseGraph 或本轮工具输出时才保留；否则自动降级为低置信经验推测。

Agent 不能直接写正式 Skill。`propose_skill` 只创建待审批提案，覆盖已有 Skill 需要二次确认。自动生成的 learned pattern 也先进入 `pending`，人工批准后才参与路由。

## 持久化与并发

- CaseGraph 使用同目录临时文件写完后原子替换。
- 同一 case 的上传、提示更新、QueryRun、insights、memory 和 tool run 共用 case 级锁；不同 case 可并行。
- Agent Session 使用 SQLite，所有成功、异常和回合耗尽路径都会显式关闭。
- MCP Server 与 Client 按稳定配置指纹复用；配置变化、禁用、删除、失败和退出都会关闭旧连接。

## 无模型配置时

没有 LLM API Key 时，聊天接口明确返回 `llm_key_required`，不会绕过 Agent 自动执行 Planner 或 learned bypass。案例管理、上传、直接 QueryRun、TCP stream、报告以及 RFC/Skills/Field Notes 管理接口仍可使用。

## RFC 完整库

完整 RFC 索引由后台任务下载，支持进度查询、重复启动去重、取消和 Range 续传。下载完成后必须通过 SQLite `quick_check`、表结构、meta 和数据计数校验，才能原子替换当前数据库。

## 数据契约

核心契约位于 `packages/shared/src/index.ts`：

- `CaseGraph`：案例的持久化事实图。
- `QueryRun`：一次确定性查询及诊断结果。
- `EvidenceCard`：绑定 pcap、frame 和 display filter 的证据。
- `PacketInsight`：确定性分析器产出的模式。
- `AgentAnswer`：结论、证据、根因、置信度和后续动作。

详细模块和路由说明见 [`architecture.md`](architecture.md)。
