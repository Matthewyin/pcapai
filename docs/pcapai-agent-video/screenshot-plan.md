# 真实截图采集计划

## 采集目标

重新启动本地 pcapAI，截取真实界面素材。截图用于后续剪辑、HyperFrames 画面合成和关键帧参考。

## 目标截图

| 文件名 | 内容 | 用途 |
|---|---|---|
| `01-workbench-home.png` | 工作台首页或新建会话界面 | 痛点后进入产品 |
| `02-uploaded-pcap-chat.png` | 上传 pcap 后的聊天界面 | 展示用户输入与附件 |
| `03-chain-analysis.png` | Chain Planner 或分析步骤输出 | 展示分析链 |
| `04-evidence-cards.png` | 证据卡片或证据详情页 | 展示证据闭环 |
| `05-wireshark-filter.png` | Wireshark filter / 证据跳转相关界面 | 展示可复核 |

## 截图要求

- 分辨率优先使用 1920x1080 或接近 16:9。
- 使用真实 pcapAI 页面，不用 mock UI。
- 页面里不要暴露真实密钥或敏感配置。
- 如果本地 LLM 不可用，仍可用 fixture pcap 和确定性分析结果做截图。

