# CLAUDE.md

本仓库的协作规范、真实架构、命令和关键边界统一维护在 [`AGENTS.md`](AGENTS.md)。Claude Code 开始工作前必须完整读取该文件，不在本文件复制第二份容易过期的架构说明。

必须遵守的最小边界：

- 所有沟通、新增注释和用户界面文案使用中文。
- 聊天主链是 Leader Agent 第一入口；Chain Planner、协议 adapters 和 learned patterns 只是 Agent 工具或专家直达能力。
- 无 LLM API Key 时聊天接口返回 `llm_key_required`，直接 QueryRun、TCP stream、报告和知识库管理接口仍可用。
- `rfcVerified=true` 必须通过本轮真实 RFC 章节读取和包 ID 校验，不能信任模型自报。
- Agent 只能提交 Skill 和 learned pattern 候选，人工批准前不得影响全局知识或未来路由。
- 同一 case 的读改写必须经过共享 case 锁，CaseGraph 使用原子写入，SQLite Session 必须显式关闭。
- 测试只能写临时目录，不得污染真实 `data/`。

常用命令：

```bash
npm install
npm run dev
npm run check
npm run test
npm run build
npm run app:build
```

发布前还需运行：

```bash
npm run pack -w apps/desktop
```
