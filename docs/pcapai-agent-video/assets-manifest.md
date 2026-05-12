# 视频素材清单

## 文档素材

- `README.md`：前期制作包说明。
- `visual-direction.md`：Data Drift 视觉方向和关键帧提示词。
- `voiceover.md`：约 115 秒中文口播稿。
- `bgm-prompt.md`：BGM 生成提示词。
- `shot-plan.md`：分镜规划。
- `screenshot-plan.md`：截图采集计划。
- `rough-cut/`：HyperFrames 115 秒粗剪工程。

## 已采集截图

| 文件 | 内容 | 用途 |
|---|---|---|
| `data-drift-keyframe.png` | Data Drift 风格关键帧预览图 | 确认视频视觉基调 |
| `01-workbench-home.png` | pcapAI 工作台首页 | 产品进入画面 |
| `02-uploaded-pcap-chat.png` | 上传两个 fixture pcap 后的聊天界面 | 上传与上下文段落 |
| `03-chain-analysis.png` | QueryRun 后的路径、诊断和证据面板 | 分析链和功能价值段落 |
| `04-evidence-cards.png` | 证据详情页 | 证据卡展示 |
| `05-wireshark-filter.png` | 当前证据和 Wireshark filter 面板 | 可复核证据闭环 |

## 截图来源

- 服务地址：`http://127.0.0.1:30023`
- API 地址：`http://127.0.0.1:30022`
- 使用 fixture：
  - `data/fixtures/multi-fault-scenario.pcap`
  - `data/fixtures/saas-cascade-fault.pcap`
- 当前演示问题：`分析这两个抓包中 TCP RST 和重传相关的异常通信对`
