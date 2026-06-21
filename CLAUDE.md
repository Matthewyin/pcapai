# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcapAI is an Agent-first packet troubleshooting chat workbench. Its primary unit is a **QueryRun** inside a chat session: uploaded pcap + user question -> chain planner -> single-step or multi-step analysis -> evidence cards -> Wireshark opener. A Chain Planner classifies questions into single-step or multi-step plans, deterministic protocol adapters handle structured queries (TCP metrics, DNS, TLS, HTTP, ICMP, UDP), and a leader agent with 3 handoff subagents (Hypothesis/Path/Protocol) handles open-ended analysis. Protocol adapter routing follows a tiered fallback: structured direct (`params.adapterId` / high-confidence learned bypass) → hardcoded regex → learned patterns → agent with tshark-query MCP. The chain execution engine (`executeChain`) runs multi-step plans with parameter binding between steps. UI and API text are in Chinese.

## Commands

```bash
npm install                # install all workspace deps
npm run launch             # 本地自用：构建前端 + 起单进程 API（同源托管前端，PCAPAI_SERVE_WEB=1）+ 开浏览器独立窗口；也可双击 pcapAI.command
npm run dev                # 开发模式：API + web（Vite HMR，双进程）using config/defaults.json
npm run build              # build all workspaces
npm run check              # type-check all workspaces
npm run test               # run tests across workspaces (if present)
npm run rag:build          # build RFC full-text index (SQLite FTS5) from RFC/ txt corpus
npm run eval               # behavioral eval against running API (golden cases in apps/api/scripts/evalCases.json); requires dev server + LLM key; [-- --case <id>] to run one
```

Individual workspace commands:
```bash
npm run dev -w apps/api    # API only (tsx watch)
npm run dev -w apps/web    # web only (vite)
npm run build -w packages/shared   # build shared schemas
```

Tests live in `apps/api/test/` and cover protocol correlations, path correlation, report builder, insight engine (30 analyzers), and builder utilities. Run with `cd apps/api && NODE_ENV=test npx tsx --test test/*.test.ts`.

## Architecture

npm workspace monorepo with three workspace groups:

### `packages/shared` — Shared schemas (`@pcapai/shared`)
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `Conversation`, `QueryRun`, `QueryPath`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`, `QueryDiagnosis`, `ProtocolCorrelation`, `EvidenceCard`, `AccessCandidateGroup`, `PacketInsight`, `TcpStreamSummary`, `ToolRun`, `ConnectionLink`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: MiniMax endpoint), tshark config, query limits, diagnosis thresholds, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

### `apps/api` — Express API + Agent runtime (`@pcapai/api`)
- **`src/config.ts`** — loads defaults from `config/defaults.json` and applies `PCAPAI_*` env overrides. Exports `apiConfig` and `updateLlmConfig()`.
- **`src/index.ts`** — Express app configured from `apiConfig`; exports `startApi()`. 当 `PCAPAI_SERVE_WEB=1` 时在 `/api` 路由后同源托管 `apps/web/dist`（含 SPA fallback），供本地 web app 模式单进程运行。
- **`scripts/launch.mjs`** + **`pcapAI.command`** — 本地启动器：构建前端 → 起单进程 API（同源托管）→ 等 health → 开 Chrome `--app` 独立窗口（无地址栏，近似桌面 app），回退系统默认浏览器。
- **`apps/desktop`** — Electron 外壳（实验性，非主路径）。已实现 sidecar/依赖检测/.pcap 关联/Keychain，但本地自用推荐 `npm run launch` 的 web app 模式。
- **`src/http/routes.ts`** — REST endpoints. Key routes:
  - `GET /api/health`
  - `GET/POST /api/settings/llm`, `GET/POST/DELETE /api/settings/llm/profiles`, `POST /api/settings/llm/test` — LLM config CRUD with profile support
  - `POST /api/cases`, `POST /api/cases/new-chat`, `GET /api/cases`, `DELETE /api/cases` — case/session CRUD, persisted under `data/cases`
  - `POST /api/cases/:caseId/attachments` — chat composer pcap upload with payload trimming via `editcap -s`; stores capture metadata and capinfos time range
  - `PUT /api/cases/:caseId/mapping-hints`, `PUT /api/cases/:caseId/time-offset-hints`
  - `POST /api/cases/:caseId/query-runs` — creates a QueryRun from user question and optional structured filters
  - `GET /api/cases/:caseId/query-runs/:queryRunId`
  - `POST /api/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/select`
  - `POST /api/cases/:caseId/query-runs/:queryRunId/open-wireshark`
  - `GET /api/cases/:caseId/tcp-streams?nodeId=xxx` — lists TCP streams
  - `GET /api/cases/:caseId/tcp-streams/:streamIndex/content?format=ascii&nodeId=xxx` — gets TCP stream content
  - `POST /api/cases/:caseId/evidence/open` — opens pcap evidence in local Wireshark via evidence-opener MCP
  - `GET /api/cases/:caseId/report` — Markdown report from case graph via `reportBuilder.ts`
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers. Both wrapped in per-case mutex (`withCaseRunLock`) serializing concurrent agent runs.
- **`src/http/composeServices.ts`** — service composition layer: wires 13 services + 2 answer builders + protocol adapters into `composeServices(deps)`. Extracted from routes.ts.
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/reportBuilder.ts`** — generates structured Markdown report from case graph: sections for query, data sources, evidence, L7 correlations, access objects, multi-node path, diagnosis checks, and Wireshark filters
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/protocolAdapters/`** — deterministic protocol-specific query subsystem:
  - `types.ts` — `ProtocolAdapter` interface and `runProtocolAdapter()` dispatcher; tiered routing: structured direct (`params.adapterId` / learned bypass) → hardcoded regex → learned patterns → agent fallback
  - `builders.ts` — shared logic: packet pair grouping, evidence card creation, `QueryRun` construction, L7-to-TCP protocol correlations (DNS→TCP, TLS SNI→TCP, HTTP Host→TCP, ICMP→TCP), and HTTP cross-connection correlation (`http_to_http` for L7 proxy/SSL offload)
  - `tcp.ts` — RST session pairs, retransmission pairs, zero-window pairs, SYN-no-SYN/ACK pairs, one-way traffic pairs, TCP issues overview (RST/retransmission/zero-window), TCP connection health matrix (full enumeration + per-connection six-dimension classification)
  - `dns.ts` — DNS failure/unresponsive transactions with rcode grouping
  - `tls.ts` — TLS handshake events (ClientHello, ServerHello, alerts) with handshake completeness checks
  - `http.ts` — HTTP transactions with status code filtering (4xx/5xx), request/response matching, and cross-connection correlation
  - `icmp.ts` — ICMP unreachable/TTL exceeded/fragmentation events
  - `udp.ts` — UDP flow aggregation by endpoint pair
- **`src/services/patternLearner.ts`** — self-improvement module: loads learned regex→adapterId pairs from `data/learned_patterns.json`; after agent fallback, uses LLM to generate regex and adapterId (no hardcoded mapping)
- **`src/services/rfcCorpus.ts` / `rfcRagService.ts` / `src/agents/rfcTools.ts`** — RFC 规范知识库（无嵌入的词法方案）：`scripts/buildRfcIndex.ts`（npm run rag:build）把 `RFC/` 下 9700+ 篇官方 txt 按章节切分入 SQLite FTS5（`data/rfc-index/rfc.db`，全量构建约 10 秒）；检索服务做 BM25 + HISTORIC/被废弃降权 + 同篇去重；Agent 侧两个进程内工具：`search_rfc`（英文关键词定位条文）与 `get_rfc_section`（精读章节原文，结论引用必须经此回读，带 RFC 编号与 §section）。hypothesisPlaybook 每行带 rfcRefs 规范锚点。REST 调试入口：`GET /api/rag/search?q=`、`GET /api/rag/status`
- **`src/services/insightEngine.ts`** — 30 deterministic analyzers: TCP lifecycle/ACK gap/timing/window trend/RST direction/handshake retry/delayed ACK/connection flood/segment anomaly/keepalive/throughput/TCP options, ICMP echo pair, HTTP status chain/header anomaly/timing/advanced, TLS handshake/advanced, DNS anomaly/advanced, cross-protocol chain, UDP, ICMP advanced, QUIC, NTP, SSH, L7 proxy detection (Via/XFF/SSL offload/TCP split), NAT heuristic (multi-target/ISN/orphan SYN). Entry point: `runLevel1Insights(graph)` returns `PacketInsight[]`. No thresholds — reports all detected patterns.
- **`src/services/tcpPreprocessor.ts`** — TCP anomaly preprocessor: extracts only anomalous TCP packets (RST, retransmission, zero window, duplicate ACK, lost segment, failed handshakes) via targeted tshark queries. Uses mapping hints to focus on relevant flows. Runs before the insight engine to keep the analysis dataset small.
- **`src/services/conversationHealth.ts`** — pure `classifyConversationHealth` function for single-conversation six-dimension TCP health classification (handshake/rst/trafficDirection/retransmission/zeroWindow/closeState). Shared between `buildQueryDiagnosis` and the `tcp_connection_health_matrix` adapter.
- **`src/mcp/tsharkQueryClient.ts`** — stdio MCP client for tshark-query; wraps 18 tool calls (including `list_tcp_conversations`, `list_tcp_streams`, `follow_tcp_stream`, `get_expert_info`). `listTcpConversationsWithMcp` accepts optional `limit` (default 100; health matrix adapter passes 5000 for full enumeration).
- **`src/mcp/evidenceOpenerClient.ts`** — stdio MCP client for evidence-opener
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime with three phases:
  1. **Chain planner** (`runChainPlanner`) — plans single-step or multi-step analysis chains; outputs `AnalysisChainPlan` with ordered steps, each referencing one of 12 intents. Requires an LLM key (requests fail fast with `llm_key_required` otherwise).
  2. **Deterministic handlers** — protocol adapters and route-level handlers handle structured queries without LLM. The chain execution engine (`executeChain` in `plannerService.ts`) orchestrates multi-step plans with parameter binding between steps via `paramsFrom` JSON path expressions.
  3. **Agent conversation** (`runPcapTroubleshootingAgent`) — uses in-process case graph tools (`src/agents/caseGraphTools.ts`, reads live graph from caseStore; memory/topology writes persist) plus a persistent `tshark-query MCP` singleton (`src/mcp/tsharkQueryMcpRuntime.ts`, reused across requests, reset on failure). Leader agent with 3 handoff subagents (Hypothesis, Path, Protocol); the leader handles interview follow-ups and report formatting itself. HypothesisAgent's diagnostic knowledge (insight catalog + hypothesis playbook) is injected dynamically based on insight types actually present in the case. Returns `AgentAnswerWithToolCalls` including tool call names for pattern learning. Uses `OpenAIProvider` with configurable base URL/model. `maxTurns` 走 config（默认 24）.
- **`src/services/plannerService.ts`** — planner service factory: `planChain` calls the chain planner, `executeChainStep` routes a single step intent, `executeChain` runs multi-step plans with SSE callbacks and exposes per-step structured facts (`ChainStepResult.data`) for `paramsFrom` binding.

### `apps/web` — React workbench (`@pcapai/web`)
Single-file React 19 app (`src/main.tsx`). Chat-first layout with session history, central message stream, bottom composer, settings, and help views. Config (`src/config.ts`) reads `__PCAPAI_WEB_CONFIG__` injected by Vite from `config/defaults.json`. Features:
- New chat creates an empty case
- Composer pcap upload via file picker, drag/drop, and paste
- Markdown rendering for finalized assistant messages (via `marked` + `dompurify`)
- Evidence cards in a new browser tab via Blob URL ("查看证据详情" button) — chat bubble keeps text analysis, link page is for Wireshark operations
- Mapping hint and time offset hint editing
- Chat-style agent Q&A with SSE streaming
- LLM settings management with profile CRUD and connectivity testing
- Dark/light theme toggle
- TCP stream viewer with list → content drill-down, client/server dual-column display
- Waterfall chart (pure SVG) for cross-protocol chain timing visualization
- Topology diagram (pure SVG) from network topology data
- Insight rendering in chat for diagnostic patterns

### `mcp/*` — MCP servers
Two stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`tshark-query`** — reads capture metadata with `capinfos`, builds display filters, and runs `tshark` for conversations, packet queries, packet details, TCP resets/retransmissions/zero-window, ICMP events, DNS packets, UDP flows, TLS events, HTTP packets, protocol listing, and network statistics. 19 tools (including `list_tcp_conversations`, `list_tcp_streams`, `follow_tcp_stream`, `get_expert_info`, `get_tshark_packet_detail`).
- **`evidence-opener`** — opens local Wireshark for a pcap path and display filter. It does not analyze packets.

## Query Pipeline

`POST /api/cases/:caseId/agent` runs:
1. **Chain planner** classifies the question and produces a single-step or multi-step `AnalysisChainPlan`
2. **Chain path**: if `planKind === "chain"`, `executeChain` runs multiple steps sequentially with parameter binding between steps; each step is a standard intent (protocol query, session query, etc.)
3. **Deterministic path**: for single-step plans, if a protocol adapter matches (hardcoded regex or learned pattern), it runs tshark queries directly, builds evidence cards and protocol correlations, writes the QueryRun, and returns without calling the LLM agent
4. **Agent fallback**: when no adapter matches, the leader agent handles the query using in-process case graph tools and tshark-query MCP, then triggers async pattern learning
5. **Agent path**: for open-ended questions (`llm_explain` intent), the leader agent hands off to Hypothesis/Path/Protocol subagents (interview and report formatting are handled by the leader itself)

`POST /api/cases/:caseId/query-runs` runs:
1. Infer or accept time/address/port/protocol filters
2. **tshark-query MCP** builds a display filter
3. **tshark-query MCP** runs `tshark` and returns matching conversations plus bounded packet evidence
4. API builds `AccessCandidateGroup`s, `QueryPath`, and deterministic `QueryDiagnosis` (handshake, RST, retransmission, zero-window, traffic direction, FIN close checks)
5. API stores `QueryRun`, selected conversation, path, diagnosis, and evidence cards
6. Browser shows evidence cards and opens packet/conversation/time range evidence through **evidence-opener MCP**

## Protocol Adapter Self-Improvement

Protocol adapter routing follows a tiered fallback:
1. **Structured direct / learned bypass** — `params.adapterId` routes directly to the target adapter. High-confidence learned patterns short-circuit the Chain Planner via `tryLearnedBypass`.
2. **Hardcoded regex** — each adapter has built-in match functions
3. **Learned patterns** — `data/learned_patterns.json` stores `{regex, adapterId}` pairs generated by LLM after agent fallback
4. **Agent fallback** — leader agent with tshark-query MCP handles the query; after success, `patternLearner` uses LLM to generate a new regex pattern

The learning module has no hardcoded tool→adapter mapping. The LLM determines both the regex pattern and the target adapterId from the question context and available adapter list.

## Key Design Constraints

- **Deterministic queries bypass the LLM** — protocol adapters (TCP metrics, DNS, TLS, HTTP, ICMP, UDP) run tshark directly and produce structured evidence cards without agent involvement.
- **Agents read case graph AND can query tshark directly** — the leader agent and subagents have access to in-process case graph tools (`caseGraphTools.ts`; reads live case data, memory/topology writes persist to caseStore) and tshark-query MCP (raw packet queries, persistent singleton connection). Protocol agent uses tshark-query tools when deterministic adapters don't match.
- **Upload does not full-parse pcap files** — large-file handling depends on capture metadata first and display-filtered tshark queries later.
- **TCP preprocessor extracts only anomalous packets** — `extractTcpAnomalies()` runs targeted tshark queries for RST, retransmission, zero window, duplicate ACK, lost segment, and failed handshakes. Uses mapping hints to focus on relevant flows. This replaces full-packet fetching to prevent LLM context overflow. Protocol adapters query tshark independently during user queries.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The chain planner classifies into single-step or multi-step plans (2-5 steps). Each step uses one of 12 intents. Steps can bind parameters from previous step results via `paramsFrom` JSON path expressions. No hard-coded scenarios — plans are dynamically generated from the case graph.
- The leader agent hands off to exactly one subagent per question. `maxTurns` 走 config（默认 24）.
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
- `QueryDiagnosis` runs deterministic checks (handshake completeness, RST, retransmission burst, zero window, bidirectional traffic, FIN close) with thresholds from `config/defaults.json` `api.diagnosis`.
- **Insight engine reports all patterns without threshold filtering** — every detected pattern is reported; severity is a visual marker only. 30 analyzers including L7 proxy and NAT heuristic detection.
- Evidence cards are shown in a new browser tab via Blob URL, not in the chat bubble. Chat is for reading conclusions; the link page is for Wireshark operations.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
