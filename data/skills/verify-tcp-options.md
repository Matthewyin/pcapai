---
name: verify-tcp-options
description: 对比两端 TCP 包的 options 字段（timestamp、SACK、MSS、WScale），验证配置是否匹配
triggers:
  - "SYN 无 SYN-ACK 且需验证 TCP options"
  - "怀疑 timestamp option 不匹配"
  - "连接建立失败需检查 options 协商"
tools_required:
  - follow_tcp_stream
  - get_packet_detail
  - get_rfc_section
---

# 验证 TCP Options 匹配

## 适用场景
当怀疑连接建立失败与 TCP options 配置差异有关时使用。典型场景：客户端发出 SYN 但服务端不回 SYN-ACK，需排除 timestamp/SACK/MSS 不匹配导致的丢包。

## 执行步骤

1. **取 SYN 包**：用 `follow_tcp_stream` 或 `query_packets(tcp.flags.syn==1)` 取出会话的 SYN 包（客户端→服务端方向的第一帧）。

2. **查看 SYN 的 options**：用 `get_packet_detail` 查看该 SYN 包的 TCP options，记录：
   - 是否含 `Timestamp`（TSopt，kind=8）
   - `MSS`（Maximum Segment Size，kind=2）值
   - `SACK Permitted`（kind=4）是否启用
   - `Window Scale`（WScale，kind=3）值

3. **取服务端 SYN-ACK（若有）的 options**：同样提取服务端回应的 SYN-ACK 包的 options。

4. **对比两端**：
   - `timestamp`：两端是否都启用。RFC 7323§3.2 规定 timestamp 是可选的，但某些实现对"对端未启用 timestamp"的 SYN 会直接丢弃。
   - `MSS`：不一致是正常的（协商取小值），非故障。
   - `WScale`：未协商不影响建立，但影响吞吐。

5. **对照 RFC 判定**：发现差异后，用 `get_rfc_section(7323, "3.2")` 回读原文，确认该差异是否违反规范。

## 判定标准

| 现象 | 结论 | RFC |
|---|---|---|
| 一端启用 timestamp，对端 SYN 被丢弃 | 可能是 timestamp 不匹配导致 | RFC 7323§3.2 |
| MSS 不一致 | 非故障，协商取小值 | RFC 9293 |
| WScale 未协商 | 非建立故障，但限吞吐 | RFC 7323§2.2 |

## 注意

- "无 SYN-ACK"不一定是 options 问题，也可能是防火墙、端口未监听、ICMP unreachable。本 skill 用于排除 options 因素，不排除其他可能。
- 必须用 `get_rfc_section` 回读原文后再引用 RFC，不凭记忆引用章节内容。
