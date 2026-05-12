# pcapAI Agent HyperFrames 粗剪

## 当前版本

- 时长：115 秒
- 画幅：1920x1080
- 风格：Data Drift
- 结构：痛点 → 为什么需要 Agent → 架构 → 技术亮点 → 产品价值 → 案例 → 总结
- v2 增强：补充用户输入、Agent 流式返回、打开 Wireshark、问题通信对定位、证据细节放大等动作镜头
- v3 增强：架构段改为 Agent Harness 组件图，突出 Case Graph、Planner、Executor、MCP Tools、Adapters、Leader/Subagents 的运行关系
- 音频：未内置，口播和 BGM 后续单独处理

## 预览

如果 HyperFrames Studio 已启动，访问：

```text
http://localhost:30025/#project/rough-cut
```

本地启动命令：

```bash
npm run dev -- --port 30025
```

## 检查结果

已通过：

```bash
npx hyperframes lint
npx hyperframes compositions
```

当前 lint 只有结构性警告：粗剪版暂时把 7 个场景放在单文件，后续精修可拆成 sub-composition。

已生成 3 张 Studio 关键帧截图用于快速验收：

- `studio-v2-19-chat-agent.png`：用户输入与 Agent 返回
- `studio-v3-39-harness.png`：Agent Harness 组件架构
- `studio-v2-81-wireshark.png`：打开 Wireshark、display filter 和异常包行
- `studio-v2-96-detail-zoom.png`：问题通信对与证据细节放大

未通过：

```bash
npx hyperframes validate
npx hyperframes inspect --at 19,39,81,96 --json
```

失败原因是 headless Chrome 启动失败。`npx hyperframes doctor` 显示 Chrome 和 FFmpeg 均存在，但当前可用内存约 0.7 GB，可能导致浏览器校验失败。Studio 的 thumbnail 接口可以正常导出关键帧。

## 已知限制

- 这是粗剪，不是最终成片。
- 没有内置配音、字幕逐字同步和 BGM。
- 过渡使用简化的 cyan scan wipe，后续可替换为更完整的 shader transition。
- 正式精修前建议拆分 `index.html`，把每个 scene 迁移到 `compositions/`。
