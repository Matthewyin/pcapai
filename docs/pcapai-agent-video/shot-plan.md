# pcapAI Agent 分镜规划

## 总体节奏

总时长建议 110-115 秒。每一段都围绕“证据链”展开，不做空泛 AI 能力介绍。

| 时间 | 模块 | 内容 | 画面 |
|---|---|---|---|
| 0-15s | 痛点 | 多节点 pcap 多、时间不齐、NAT/代理改写、人工过滤慢 | 散落 pcap、IP/端口/时间线混杂、Wireshark 过滤器闪过 |
| 15-28s | 为什么需要 pcapAI Agent | 不是让模型猜，而是组织证据链 | pcap 文件流入 pcapAI 工作台，形成 case graph |
| 28-50s | 架构 | Web、API、Chain Planner、Protocol Adapters、MCP、Wireshark | 架构图逐层点亮 |
| 50-72s | 技术亮点 | 确定性适配器、QueryRun、证据卡、路径关联、Agent fallback | TCP/DNS/TLS/HTTP/ICMP/UDP 节点依次激活 |
| 72-88s | 功能价值 | 中文问答、Wireshark filter、证据卡、置信度、缺失上下文 | 聊天气泡、证据卡、路径图、filter 高亮 |
| 88-108s | 案例 | 上传多节点 pcap，提问“为什么访问失败”，定位 RST/重传/路径断点 | 上传、分析链执行、证据卡、Wireshark 打开 |
| 108-115s | 总结 | 结论可读、证据可点、路径可复核 | 标题回归，三句总结 |

## 关键字幕

- 多节点抓包，难点是证据串联。
- 能确定的，不交给模型猜。
- 每一次提问，都是一个 QueryRun。
- 结论必须能回到 packet、filter、frame。
- Agent 解释证据链，不替代证据。

