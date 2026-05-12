# pcapAI Agent Rough Cut Design

## Style Prompt

Data Drift 风格，面向内部技术汇报。画面是深色数据工作台，不是抽象 AI 海报。真实 pcapAI 截图作为主素材，叠加细线、协议节点、证据卡、过滤器和路径流动。整体克制、清晰、可读，强调“证据链”和“可复核”。

## Colors

- Background: `#0a0a0a`
- Panel: `#0f172a`
- Foreground: `#e5f7fb`
- Muted text: `#8fb7c4`
- Evidence cyan: `#06b6d4`
- Agent purple: `#7c3aed`
- Anomaly amber: `#f59e0b`

## Typography

- Display: `Rajdhani`, fallback `Arial Narrow`, `system-ui`
- Data/filter: `IBM Plex Mono`, fallback `SFMono-Regular`, `monospace`
- 数字和过滤器使用 tabular numbers。

## Motion

- 场景使用柔和的 grid dissolve / cyan scan wipe 过渡。
- 每个场景的元素从最终布局位置入场，不做提前退出动画。
- 证据、路径、协议节点依次点亮，体现分析链。

## What NOT to Do

- 不使用抽象 AI 大脑、机器人、赛博朋克街景。
- 不使用大面积紫蓝渐变文字。
- 不把真实产品截图缩成看不清的小装饰。
- 不用红色大面积渲染故障，异常只用 amber 点明。

