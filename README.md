# pcapAI

pcapAI 是一个 Agent-first 的本地抓包排障工作台。用户上传 pcap 后可在聊天中提问；系统用 tshark 提取确定性事实，形成 QueryRun、证据卡、根因与 Wireshark 过滤器。

## 当前主流程

```text
上传 pcap + 用户提问
  → Leader Agent 作为聊天第一入口
  → 先检索 Field Notes / Skills
  → 按需调用 pcapai_ 确定性工具或 tshark-query MCP
  → 读取 RFC 原文章节验证协议结论
  → 输出可回溯的证据、根因和后续建议
```

Leader 可交接给 Hypothesis、Path、Protocol 三个专家 Agent。Chain Planner、协议 adapters 和 learned patterns 仍保留为 Agent 工具或专家直达能力，但不在聊天入口前拦截用户问题。

## 快速开始

```bash
npm install
npm run dev
```

默认打开 `http://127.0.0.1:30023`。运行参数集中在 `config/defaults.json`，可用 `PCAPAI_*` 环境变量覆盖。

### macOS 桌面版

首次发布提供 Apple Silicon（arm64）和 Intel（x64）DMG，可从 [GitHub Releases](https://github.com/Matthewyin/pcapai/releases) 获取。应用在本机运行，pcap、案例、模型配置和下载的 RFC 库不会上传到项目服务器；模型请求是否离开本机取决于你配置的 OpenAI 兼容服务。

`v0.1.0` 尚未使用 Apple Developer 证书签名和公证。首次打开若被 Gatekeeper 阻止，请在 Finder 中右键应用并选择“打开”，确认后即可运行。

从源码打包：

```bash
npm run app:build
npm run pack -w apps/desktop
```

使用聊天 Agent 前，在“设置 → 模型配置”中填写 OpenAI 兼容的 Base URL、API Key 和模型名称。也可以复制 `.env.example` 为 `.env` 后配置 `PCAPAI_LLM_API_KEY`。

### 无 API Key 时的能力边界

- 可以新建/管理案例、上传 pcap、维护映射提示和时间偏移。
- 可以使用直接的 QueryRun、TCP stream、报告、RFC/Skills/Field Notes 管理接口及本地确定性数据能力。
- 聊天入口 `/api/cases/:caseId/agent` 与 `/agent/stream` 不会启动 Planner、Agent 或自动确定性执行器，而是明确返回 `llm_key_required`，提示先配置模型。
- 不会进行 Agent 访谈、开放式归因、RFC 语义检索编排或自动学习。

## 核心边界

### 证据与 RFC

- 包事实由 tshark-query 或 `pcapai_` 确定性工具产生，LLM 不负责猜测包事实。
- `rfcVerified=true` 只有在本轮真实调用 `get_rfc_section`、文档与章节匹配，且根因引用的包 ID 确实存在于 CaseGraph 或本轮工具输出时才保留。
- 伪造 RFC 引用、章节错配、缺少包证据都会降级为 `rfcVerified=false`，并标记“经验推测，无已验证 RFC 依据”。

### 知识写入审批

- Agent 只能通过 `propose_skill` 提交 Skill 提案，不能直接写全局 Skill 文件。
- 用户在设置页批准后提案才生效；覆盖已有 Skill 必须再次显式确认。
- Agent 自动生成的 learned pattern 先进入 `pending`，批准后才参与确定性路由；可禁用、拒绝或删除。

### 持久化与并发

- CaseGraph 写入使用同目录临时文件 + 原子 rename，失败时保留旧文件。
- 所有同 case 的读改写共用 per-case 锁；同一 case 串行，不同 case 可并行。
- SQLite Session 在正常结束、异常和回合预算耗尽收口时都会关闭。
- MCP Agent server 与 Client 按连接配置指纹复用；配置变化、禁用、删除、重置和进程退出都会关闭旧连接。

### RFC 完整库下载

- `POST /api/rag/download/start` 立即返回后台任务状态，不等待下载完成。
- 支持状态轮询、重复启动去重、取消、Range 断点续传和删除。
- 下载完成后先执行 SQLite `quick_check`、表结构、meta 与实际计数校验；只有校验通过才原子替换当前完整库，失败不会破坏现有库。

## 目录

```text
apps/web               React 19 工作台
apps/api               Express API、Agent runtime、确定性服务
apps/desktop           Electron 桌面壳
mcp/tshark-query       tshark/capinfos 查询 MCP
mcp/evidence-opener    Wireshark 打开器 MCP
packages/shared        Zod schemas 与共享 TypeScript 类型
config/defaults.json   集中运行配置
data/skills            内置 Skills 种子
data/field-notes       Field Notes 种子与索引
```

## 主要能力

- TCP：连接生命周期、RST、重传、Zero Window、握手、单向流、连接健康矩阵。
- DNS/TLS/HTTP/ICMP/UDP：协议事件、事务匹配和异常检查。
- 跨协议关联：DNS → TCP、TLS SNI → TCP、HTTP Host → TCP，以及 HTTP 跨连接代理关联。
- Insight Engine：29 个确定性分析器，覆盖 TCP、HTTP、TLS、DNS、ICMP、UDP、QUIC、NTP、SSH、NAT 与 L7 代理启发式。
- 证据卡：绑定 pcap、frame、display filter，可跳转本地 Wireshark。
- 三层知识：Skills（方法论）→ Field Notes（案例）→ packet facts（数据），RFC 作为规范边界。

## 常用命令

```bash
npm run dev
npm run check
npm run test
npm run build
npm run app:build
```

API 测试启动器会先检测 `better-sqlite3` 的 Node ABI；若当前 Node 与桌面依赖不匹配，会自动切换到项目自带的 Electron Node 运行测试，不会重编译或破坏桌面依赖。Field Notes、Skills、Session、CaseGraph 与下载测试均写系统临时目录，不修改真实 `data/`。

## 文档

- [架构说明](docs/architecture.md)
- [产品设计](docs/design.md)
- [Agent 排障方法论](docs/agent-methodology.md)
- [更新记录](CHANGELOG.md)

## 技术栈

TypeScript、React 19、Express、Vite、Electron、OpenAI Agents SDK、MCP、tshark/Wireshark、SQLite/FTS5。
