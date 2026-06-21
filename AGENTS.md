# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

pcapAI is an Agent SDK-first packet troubleshooting chat workbench. Its primary unit is a **QueryRun** inside a chat session: uploaded pcap + user question → **Agent (first entry)** → QueryRun / evidence cards / root causes / Wireshark opener. The Agent is the sole brain (no chain planner / learned pattern interception in front of it). It operates over a **three-layer knowledge system**: Skills (methodology layer, reusable troubleshooting SOPs in `data/skills/*.md`) → Field Notes (case layer, symptom→cause→RFC in `data/field-notes/`) → packet facts (data layer via tshark-query MCP). The leader agent with 3 handoff subagents (Hypothesis/Path/Protocol) handles open-ended analysis. RFC is the anti-hallucination boundary: root cause conclusions must either reference an RFC section (verified via `get_rfc_section`) or be explicitly marked as speculation (`rfcVerified: false`). Cross-turn context is managed by the SDK `Session` interface (SQLite-backed, `apps/api/src/agents/sqliteSession.ts`) with application-layer compaction. Deterministic protocol adapters (TCP/DNS/TLS/HTTP/ICMP/UDP) and the chain planner are retained as Agent tools / expert direct channels, but no longer intercept the user query. UI and API text are in Chinese.

## Commands

```bash
npm install                # install all workspace deps
npm run dev                # start API + web using config/defaults.json
npm run build              # build all workspaces
npm run check              # type-check all workspaces
npm run test               # run tests across workspaces (if present)
```

Individual workspace commands:
```bash
npm run dev -w apps/api    # API only (tsx watch)
npm run dev -w apps/web    # web only (vite)
npm run build -w packages/shared   # build shared schemas
```

Tests live in `apps/api/test/` and cover AgentToolRegistry tool traces, protocol correlations, path correlation, report builder, insight engine (29 analyzers), and builder utilities. Run with `cd apps/api && NODE_ENV=test npx tsx --test test/*.test.ts`.

## Architecture

npm workspace monorepo with three workspace groups:

### `packages/shared` — Shared schemas (`@pcapai/shared`)
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `Conversation`, `QueryRun`, `QueryPath`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`, `QueryDiagnosis`, `ProtocolCorrelation`, `EvidenceCard`, `AccessCandidateGroup`, `PacketInsight`, `TcpStreamSummary`, `ToolRun`, `ConnectionLink`, `AnalysisChainPlan`, `AnalysisChainStep`, `ChainStepResult`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: MiniMax endpoint), tshark config, query limits, diagnosis thresholds, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

### `apps/api` — Express API + Agent runtime (`@pcapai/api`)
- **`src/config.ts`** — loads defaults from `config/defaults.json` and applies `PCAPAI_*` env overrides. Exports `apiConfig` and `updateLlmConfig()`.
- **`src/index.ts`** — Express app configured from `apiConfig`.
- **`src/http/routes.ts`** — REST endpoints + SSE streaming. Key routes:
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
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers with chain execution. Both agent endpoints are wrapped in a per-case mutex (`withCaseRunLock`) that serializes concurrent agent runs for the same case, preventing read-modify-write races on the in-memory graph cache (QueryRun/insights clobbering).
- **`src/http/composeServices.ts`** — service composition layer extracted from routes.ts. Wires 13 services + 2 answer builders + protocol adapters into a single `composeServices(deps)` factory receiving `loadGraph`/`cacheCase`/`agentRuntimeStatus` as shared state. Also owns `formatBeijingTime`, `buildAgentQuestion`, `syncMemoryFromQueryRuns`, and `updateMemory`. routes.ts stays a thin HTTP handler → service method mapping.
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/reportBuilder.ts`** — generates structured Markdown report from case graph
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/protocolAdapters/`** — 6 deterministic protocol-specific query subsystems used behind AgentToolRegistry / `pcapai_` tools:
  - `types.ts` — `ProtocolAdapter` interface and `runProtocolAdapter()` dispatcher; tiered routing: structured direct (`params.adapterId` / learned bypass) → hardcoded regex match → learned patterns from `data/learned_patterns.json` → agent fallback
  - `builders.ts` — shared logic: packet pair grouping, evidence card creation, `QueryRun` construction, L7-to-TCP protocol correlations (DNS→TCP, TLS SNI→TCP, HTTP Host→TCP, ICMP→TCP) and HTTP cross-connection correlation (`http_to_http` for L7 proxy/SSL offload scenarios)
  - `tcp.ts` — RST session pairs, retransmission pairs, zero-window pairs, SYN-no-SYN/ACK pairs, one-way traffic pairs, TCP issues overview (RST/retransmission/zero-window), TCP connection health matrix (full conversation enumeration with per-connection six-dimension health classification: normal/handshake-failed/RST/retransmission-burst/zero-window/one-way)
  - `dns.ts` — DNS failure/unresponsive transactions with rcode grouping and multi-check output
  - `tls.ts` — TLS handshake events (ClientHello, ServerHello, alerts) with handshake completeness checks and multi-check output
  - `http.ts` — HTTP transactions with status code filtering (4xx/5xx), request/response matching, multi-check output, and cross-connection correlation via `buildHttpCrossConnectionCorrelation()`
  - `icmp.ts` — ICMP unreachable/TTL exceeded/fragmentation events
  - `udp.ts` — UDP flow aggregation by endpoint pair
- **`src/services/insightEngine.ts`** — 29 deterministic analyzers run lazily through `loadGraphWithInsights()` when current graph has packet samples and no existing insights: TCP lifecycle/ACK gap/timing/window trend/RST direction/handshake retry/delayed ACK/connection flood/segment anomaly/keepalive/throughput/TCP options, ICMP echo pair, HTTP status chain/header anomaly/timing/advanced, TLS handshake/advanced, DNS anomaly/advanced, cross-protocol chain, UDP, ICMP advanced, QUIC, NTP, SSH, L7 proxy detection (Via/XFF/SSL offload/TCP connection split), NAT heuristic (multi-target/ISN jump/orphan SYN). No threshold filtering — all detected patterns are reported.
- **`src/services/tcpPreprocessor.ts`** — TCP anomaly preprocessor that replaces full-packet fetching. Extracts only anomalous TCP packets (RST, retransmission, zero window, duplicate ACK, lost segment, failed handshakes) via targeted tshark queries. Uses mapping hints to focus on relevant flows when available. This keeps the analysis dataset small (hundreds vs tens of thousands of packets) so the insight engine and LLM agent don't exceed context limits.
- **`src/services/conversationHealth.ts`** — pure `classifyConversationHealth` function for single-conversation six-dimension TCP health classification (handshake/rst/trafficDirection/retransmission/zeroWindow/closeState). Shared between `buildQueryDiagnosis` (query-run deep diagnosis) and the `tcp_connection_health_matrix` adapter so both use the same verdict criteria.
- **`src/services/patternLearner.ts`** — self-improvement module for protocol adapter routing:
  - `loadLearnedPatterns()` — loads learned regex→adapterId pairs from `data/learned_patterns.json`
  - `learnFromAgentRun()` — after agent handles a fallback query, uses LLM to generate a regex pattern and target adapterId; validates and persists to JSON
  - No hardcoded tool→adapter mapping; LLM determines both regex and adapterId from question context
- **`src/services/agentToolRegistryService.ts`** — shared deterministic tool registry for planner execution and OpenAI Agents SDK function tools. Tool names use the `pcapai_` prefix and every registry execution writes `ToolRun(kind=tool)`.
- **`src/services/protocolEventQueryService.ts`** — protocol adapter orchestration, including adapter disambiguation, learned pattern fallback, agent fallback, and multi-protocol answer merging.
- **`src/services/queryRunApiService.ts`** — QueryRun HTTP orchestration for create/get/activate/select/packet list/open Wireshark, keeping `routes.ts` focused on HTTP status and JSON conversion.
- **`src/mcp/tsharkQueryClient.ts`** — stdio MCP client for tshark-query; wraps 18 tool calls (including `list_tcp_conversations`, `list_tcp_streams`, `follow_tcp_stream`, `get_expert_info`). `listTcpConversationsWithMcp` accepts an optional `limit` (default 100 from MCP; the health matrix adapter passes 5000 for full enumeration).
- **`src/mcp/evidenceOpenerClient.ts`** — stdio MCP client for evidence-opener
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime with three phases:
  1. **Chain planner** (`runChainPlanner`) — plans single-step or multi-step analysis chains; outputs `AnalysisChainPlan` with ordered steps, each referencing one of 12 intents. Requires an LLM key (requests fail fast with `llm_key_required` otherwise).
  2. **Deterministic tools** — AgentToolRegistry executes structured capabilities without asking the LLM to infer packet facts. The chain execution engine (`executeChain` in `plannerService.ts`) orchestrates multi-step plans with parameter binding via `paramsFrom` JSON path expressions and graph reload between steps.
  3. **Agent conversation** (`runPcapTroubleshootingAgent`) — uses in-process case graph tools (`src/agents/caseGraphTools.ts`, reads live graph from caseStore; memory/topology writes persist), a persistent `tshark-query MCP` singleton (`src/mcp/tsharkQueryMcpRuntime.ts` with connect retry), and injects `pcapai_` local tools. Leader agent with 3 handoff subagents (Hypothesis, Path, Protocol); the leader handles interview follow-ups and report formatting itself. Protocol agent can call tshark-query tools directly for packet data. Returns `AgentAnswerWithToolCalls` including extracted tool call names for pattern learning. Uses `OpenAIProvider` with configurable base URL/model. `maxTurns` is config-driven (default 24 via `config/defaults.json` `llm.maxTurns`). On turn-budget exhaustion, a no-tool `AnswerCloserAgent` synthesizes a final answer from collected tool results (with a try/catch fallback to plain text if the closer itself fails).
- **`src/services/plannerService.ts`** — planner service factory: `planChain` calls the chain planner, `executeChainStep` delegates a single step intent to AgentToolRegistry via `executeToolIntent`, `executeChain` runs multi-step plans with SSE callbacks, graph reload, and parameter binding. Falls back to local pattern matching when no LLM key.

### `apps/web` — React workbench (`@pcapai/web`)
Single-file React 19 app (`src/main.tsx`). Chat-first layout with session history, central message stream, bottom composer, settings, and help views. Config (`src/config.ts`) reads `__PCAPAI_WEB_CONFIG__` injected by Vite from `config/defaults.json`. Features:
- New chat creates an empty case
- Composer pcap upload via file picker, drag/drop, and paste
- Markdown rendering for finalized assistant messages (via `marked` + `dompurify`)
- Evidence cards rendered in a new browser tab via Blob URL ("查看证据详情" button) — chat bubble keeps all text analysis, link page is for Wireshark operations
- Mapping hint and time offset hint editing
- Chat-style agent Q&A with SSE streaming and chain step progress
- LLM settings management with profile CRUD and connectivity testing
- Dark/light theme toggle
- Report export
- TCP stream viewer with list → content drill-down, client/server dual-column display
- Waterfall chart (pure SVG) for cross-protocol chain timing visualization
- Topology diagram (pure SVG) from network topology data
- Insight rendering in chat for diagnostic patterns

### `mcp/*` — MCP servers
Two stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`tshark-query`** — reads capture metadata with `capinfos`, builds display filters, and runs `tshark` for conversations, packet queries, packet details, TCP resets/retransmissions/zero-window, ICMP events, DNS packets, UDP flows, TLS events, HTTP packets, protocol listing, and network statistics. 19 tools (including `list_tcp_streams`, `follow_tcp_stream`, `get_expert_info`, `get_tshark_packet_detail`).
- **`evidence-opener`** — opens local Wireshark for a pcap path and display filter. It does not analyze packets.

## Query Pipeline

`POST /api/cases/:caseId/agent` runs:
1. **Chain planner** classifies the question and produces a single-step or multi-step `AnalysisChainPlan`
2. **Chain path**: if `planKind === "chain"`, `executeChain` runs multiple steps sequentially with parameter binding between steps and graph reload; auto-synthesis appends LLM interpretation if chain has no `llm_explain` step
3. **Deterministic tool path**: for single-step plans, AgentToolRegistry executes the matching `pcapai_` tool. If a protocol adapter matches (hardcoded regex or learned pattern), it runs tshark queries, builds evidence cards and protocol correlations, writes the QueryRun, and records ToolRun.
4. **Agent fallback**: when no adapter matches (hardcoded or learned), the leader agent handles the query using in-process case graph tools and tshark-query MCP, then triggers async pattern learning for future routing
5. **Agent path**: for open-ended questions (`llm_explain` intent), the leader agent hands off to one of 3 subagents (Hypothesis/Path/Protocol)

`POST /api/cases/:caseId/query-runs` runs:
1. Infer or accept time/address/port/protocol filters
2. **tshark-query MCP** builds a display filter
3. **tshark-query MCP** runs `tshark` and returns matching conversations plus bounded packet evidence
4. API builds `AccessCandidateGroup`s, `QueryPath`, and deterministic `QueryDiagnosis`
5. API stores `QueryRun`, selected conversation, path, diagnosis, and evidence cards
6. Browser shows evidence cards and opens packet/conversation/time range evidence through **evidence-opener MCP**

## Protocol Adapter Self-Improvement

Protocol adapter routing follows a tiered fallback:
1. **Structured direct / learned bypass** — `params.adapterId` routes directly to the target adapter, skipping regex inference. High-confidence learned patterns (`hitCount >= learnedBypassMinHits`) short-circuit the Chain Planner entirely via `tryLearnedBypass`, passing `{ adapterId }` to `executeChainStep`.
2. **Hardcoded regex** — each adapter has built-in match functions
3. **Learned patterns** — `data/learned_patterns.json` stores `{regex, adapterId}` pairs generated by LLM after agent fallback
4. **Agent fallback** — leader agent with tshark-query MCP handles the query; after success, `patternLearner` uses LLM to generate a new regex pattern

The learning module (`src/services/patternLearner.ts`) has no hardcoded tool→adapter mapping. The LLM determines both the regex pattern and the target adapterId from the question context and available adapter list.

## Key Design Constraints

- **Deterministic tools bypass LLM fact inference** — protocol adapters (TCP/DNS/TLS/HTTP/ICMP/UDP) run tshark directly and produce structured evidence cards. Planner and Agents SDK can both invoke those tools through AgentToolRegistry.
- **Agents read case graph AND can query tshark directly** — the leader agent and subagents have access to in-process case graph tools (`caseGraphTools.ts`; reads live case data, memory/topology writes persist to caseStore) and tshark-query MCP (raw packet queries, persistent singleton connection). Protocol agent uses tshark-query tools when deterministic adapters don't match.
- **Upload does not full-parse pcap files** — large-file handling depends on capture metadata first and display-filtered tshark queries later.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The chain planner classifies into single-step or multi-step plans (2-5 steps). Each step uses one of 12 intents. Steps can bind parameters from previous step results via `paramsFrom` JSON path expressions. No hard-coded scenarios — plans are dynamically generated from the case graph.
- The leader agent hands off to exactly one subagent per question. `maxTurns` is config-driven (default 24).
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
- `QueryDiagnosis` runs deterministic checks (handshake completeness, RST, retransmission burst, zero window, bidirectional traffic, FIN close) with thresholds from `config/defaults.json` `api.diagnosis`.
- **Insight engine reports all patterns without threshold filtering** — every detected pattern is reported; severity is a visual marker only. 29 analyzers including L7 proxy and NAT heuristic detection.
- **TCP preprocessor extracts only anomalous packets** (RST, retransmission, zero window, duplicate ACK, lost segment, failed handshakes) via targeted tshark queries before running the insight engine. Uses mapping hints to focus on relevant flows. This keeps the analysis dataset small (hundreds vs tens of thousands) and prevents LLM context overflow. Protocol adapters query tshark independently during user queries.
- HTTP adapter produces `http_to_http` cross-connection correlations alongside standard L7→TCP correlations, identifying L7 proxy/SSL offload scenarios where the same request appears on two independent TCP connections.
- Graph reload between chain steps ensures subsequent steps can read QueryRuns written by previous steps.
- Auto-synthesis: when a chain has no `llm_explain` step but LLM is configured, AgentRuntimeService appends LLM interpretation after chain completes.
- Evidence cards are shown in a new browser tab via Blob URL, not in the chat bubble. Chat is for reading conclusions; the link page is for Wireshark operations.
