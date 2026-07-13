# 更新记录

## v0.1.0 — 2026-07-14

pcapAI 首个公开版本，提供 macOS 桌面应用和本地开发模式。

### 核心能力

- Agent-first 抓包排障：Leader Agent 可交接 Hypothesis、Path、Protocol 专家。
- TCP、DNS、TLS、HTTP、ICMP、UDP 等确定性协议分析及 29 个 Insight 分析器。
- QueryRun、证据卡、TCP stream、跨协议瀑布图、网络拓扑和 Wireshark 跳转。
- Skills、Field Notes、packet facts 三层知识体系，RFC 原文作为规范边界。

### 可靠性与安全边界

- MCP Server/Client 按稳定配置复用，配置变化、调用失败或退出时正确关闭。
- 模型自报的 RFC 引用经过真实章节读取和证据包 ID 硬校验。
- Agent 生成的 Skill 与 learned pattern 必须经过人工审批。
- CaseGraph 原子写入，同 case 读改写串行，SQLite Session 全路径关闭。
- SYN/SYN-ACK 重传统计与 tshark 标记口径一致。

### 桌面与数据

- macOS arm64 与 x64 DMG。
- RFC 完整库后台下载，支持取消、断点续传、完整性校验和安全替换。
- 测试数据完全隔离，不写入用户的真实 `data/`。

### 验证

- 类型检查通过。
- 199 项自动化测试通过。
- Web、API、MCP 和 Electron 构建通过。

### 已知限制

- `v0.1.0` 未使用 Apple Developer 证书签名和公证，首次打开需要在 Finder 中右键选择“打开”。
- 当前使用 Electron 默认应用图标。
