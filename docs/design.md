# pcapAI 首版设计方案

## 目标

pcapAI 首版是一个本地浏览器工作台，用于离线分析 `client -> server` 访问失败问题。

用户上传多节点 pcap/pcapng 和最小网络上下文后，系统生成确定性的 `case graph`。Agent 只读取 `case graph` 和 packet detail API，负责解释证据链、追问缺失上下文、生成报告，不直接解析原始 pcap。

## 首版范围

首版聚焦三类问题：

- SYN 在某节点之后消失。
- SYN 已到达但没有看到 SYN-ACK。
- RST、ICMP unreachable、单方向缺包导致访问失败。

首版支持：

- 多节点抓包导入。
- 手工录入抓包节点、接口方向、抓包位置。
- 手工录入 NAT、SLB、代理、网关、隧道等映射线索。
- 生成 `case graph`、路径图、事件时间线、finding、packet evidence。
- 浏览器查看路径、证据、Agent 解释和报告。

首版不做：

- 实时抓包。
- 访问慢性能诊断。
- 自动发现完整网络拓扑。
- Agent 直接读取 pcap 或运行 shell。
- 自研底层 pcap decoder。

## 用户流程

1. 用户在浏览器创建 case，填写 client、server、协议、端口、时间窗口。
2. 用户上传一个或多个 pcap/pcapng，并为每个文件填写 `CaptureNode`。
3. 用户补充可选 `MappingHint`，例如 NAT 前后地址、SLB VIP、代理出口地址。
4. 后端调用 MCP server 解析数据包、格式化摘要、建立访问链条、生成诊断 finding。
5. 前端展示路径图、事件时间线、finding、packet 证据引用。
6. 用户向 Agent 提问，Agent 基于 `case graph` 解释当前判断或追问缺失信息。
7. 用户导出报告。

## 数据模型

核心数据契约由 `packages/shared/src/index.ts` 定义，后端、前端、MCP server 都围绕同一份语义工作。

- `CaseSpec`：case 名称、目标 client/server、端口、协议、时间窗口。
- `CaptureNode`：节点名、角色、pcap 文件、接口方向、抓包位置。
- `MappingHint`：NAT、SLB、代理、网关、隧道等已知转换线索。
- `PacketSummary`：frame number、timestamp、pcap 来源、五元组、协议、TCP flags、seq/ack、长度、摘要。
- `SessionSegment`：单节点观察到的会话片段。
- `SessionLink`：跨节点候选关联，包含匹配依据、反证、置信度。
- `EvidenceEvent`：SYN、SYN-ACK、RST、ICMP、缺失观察、NAT 映射、时间偏移等事件。
- `Finding`：问题判断、影响节点、证据引用、置信度、下一步人工验证动作。
- `PathGraph`：节点、边、会话流向、地址转换点、异常点。

## 分析原则

系统判断必须由确定性管线生成，Agent 不能替代证据计算。

确定性管线负责：

- 从 pcap 中读取 packet 级事实。
- 建立单节点 session segment。
- 做跨节点候选匹配。
- 应用 NAT/SLB/proxy mapping hint。
- 输出 evidence、finding、confidence。

Agent 负责：

- 解释 `case graph`。
- 追问缺失上下文。
- 把 evidence 组织成可读报告。
- 引导用户下一步人工验证。

## 置信度策略

首版只输出三档置信度：

- `high`：多个 packet 事实或明确 mapping hint 支撑，且没有明显反证。
- `medium`：存在可解释关联，但缺少关键上下文或只有单侧证据。
- `needs_context`：缺接口方向、节点角色、时间窗口、NAT/SLB 线索，不能给确定结论。

没有证据时不输出确定结论。缺失观察必须标明覆盖范围和前提，例如“该节点在给定时间窗口未观察到匹配 SYN”。

## 首版验收

首版可验收的最小能力：

- `npm install && npm run dev` 可以启动 API 和 Web。
- 健康检查能显示 `tshark`、Zeek 可用性。
- 上传或示例 case 能生成 `case graph`。
- finding 能点回 evidence id 和 packet/frame 来源。
- Agent 回答只引用 `case graph` 中的 evidence，不编造 packet。
- 缺少 NAT、节点角色、接口方向时，Agent 明确追问。
