# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

pcapAI is an Agent-first packet troubleshooting chat workbench. Its primary unit is a **QueryRun** inside a chat session: uploaded pcap + user question -> chain planner -> single-step or multi-step analysis -> evidence cards -> Wireshark opener. A Chain Planner classifies questions into single-step or multi-step plans (2-5 steps), deterministic protocol adapters handle structured queries (TCP/DNS/TLS/HTTP/ICMP/UDP), and a leader agent with 5 subagents handles open-ended analysis. Protocol adapter routing follows a three-tier fallback: hardcoded regex → learned patterns → agent with tshark-query MCP. The chain execution engine (`executeChain`) runs multi-step plans with parameter binding between steps via `paramsFrom` JSON path expressions and graph reload between steps. UI and API text are in Chinese.

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

Tests live in `apps/api/test/` and cover protocol correlations, path correlation, and report builder.

## Architecture

npm workspace monorepo with three workspace groups:

### `packages/shared` — Shared schemas (`@pcapai/shared`)
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `Conversation`, `QueryRun`, `QueryPath`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`, `QueryDiagnosis`, `ProtocolCorrelation`, `EvidenceCard`, `AccessCandidateGroup`, `ToolRun`, `AnalysisChainPlan`, `AnalysisChainStep`, `ChainStepResult`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: Doubao/ByteDance Ark endpoint), tshark config, query limits, diagnosis thresholds, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

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
  - `POST /api/cases/:caseId/evidence/open` — opens pcap evidence in local Wireshark via evidence-opener MCP
  - `GET /api/cases/:caseId/report` — Markdown report from case graph via `reportBuilder.ts`
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers with chain execution
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/reportBuilder.ts`** — generates structured Markdown report from case graph
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/protocolAdapters/`** — 6 deterministic protocol-specific query subsystems (bypass LLM):
  - `types.ts` — `ProtocolAdapter` interface and `runProtocolAdapter()` dispatcher; three-tier routing: hardcoded regex match → learned patterns from `data/learned_patterns.json` → agent fallback
  - `builders.ts` — shared logic: packet pair grouping, evidence card creation, `QueryRun` construction, L7-to-TCP protocol correlations (DNS→TCP, TLS SNI→TCP, HTTP Host→TCP)
  - `tcp.ts` — RST session pairs, retransmission pairs, zero-window pairs, SYN-no-SYN/ACK pairs, one-way traffic pairs, TCP issues overview
  - `dns.ts` — DNS failure/unresponsive transactions with rcode grouping and multi-check output
  - `tls.ts` — TLS handshake events (ClientHello, ServerHello, alerts) with handshake completeness checks and multi-check output
  - `http.ts` — HTTP transactions with status code filtering (4xx/5xx), request/response matching, and multi-check output
  - `icmp.ts` — ICMP unreachable/TTL exceeded/fragmentation events
  - `udp.ts` — UDP flow aggregation by endpoint pair
- **`src/services/patternLearner.ts`** — self-improvement module for protocol adapter routing:
  - `loadLearnedPatterns()` — loads learned regex→adapterId pairs from `data/learned_patterns.json`
  - `learnFromAgentRun()` — after agent handles a fallback query, uses LLM to generate a regex pattern and target adapterId; validates and persists to JSON
  - No hardcoded tool→adapter mapping; LLM determines both regex and adapterId from question context
- **`src/mcp/tsharkQueryClient.ts`** — stdio MCP client for tshark-query; wraps 15 tool calls
- **`src/mcp/evidenceOpenerClient.ts`** — stdio MCP client for evidence-opener
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime with three phases:
  1. **Chain planner** (`runChainPlanner`) — plans single-step or multi-step analysis chains; outputs `AnalysisChainPlan` with ordered steps, each referencing one of 12 intents. Falls back to single-step `runIntentPlanner` when no LLM key.
  2. **Deterministic handlers** — protocol adapters and route-level handlers handle structured queries without LLM. The chain execution engine (`executeChain` in `plannerService.ts`) orchestrates multi-step plans with parameter binding between steps via `paramsFrom` JSON path expressions and graph reload between steps.
  3. **Agent conversation** (`runPcapTroubleshootingAgent`) — creates temp file with case graph JSON, launches both `case-graph MCP` and `tshark-query MCP` via stdio. Leader agent with 5 handoff subagents (Triage, Evidence, Path, Protocol, Report), all sharing both MCP servers. Protocol agent can call tshark-query tools directly for packet data. Returns `AgentAnswerWithToolCalls` including extracted tool call names for pattern learning. Uses `OpenAIProvider` with configurable base URL/model. `maxTurns: 8`.
- **`src/services/plannerService.ts`** — planner service factory: `planChain` calls the chain planner, `executeChainStep` routes a single step intent (12 intents), `executeChain` runs multi-step plans with SSE callbacks, graph reload, and parameter binding. Falls back to local pattern matching when no LLM key.

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

### `mcp/*` — MCP servers
Three stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`tshark-query`** — reads capture metadata with `capinfos`, builds display filters, and runs `tshark` for conversations, packet queries, packet details, TCP resets/retransmissions/zero-window, ICMP events, DNS packets, UDP flows, TLS events, HTTP packets, protocol listing, and network statistics. 15 tools.
- **`evidence-opener`** — opens local Wireshark for a pcap path and display filter. It does not analyze packets.
- **`case-graph`** — Read-only MCP server for agents. Reads case graph from temp file set via `PCAPAI_CASE_GRAPH_PATH`. 16 tools: `load_case_graph`, `get_case_statistics`, `get_query_runs`, `get_query_run`, `get_active_query_run`, `get_conversation`, `get_query_diagnosis`, `get_path_diagnosis`, `get_protocol_correlations`, `get_evidence_cards`, `get_finding`, `get_evidence`, `get_session_link`, `get_packet_detail`, `explain_path`, `suggest_next_query`, `export_report`.

## Query Pipeline

`POST /api/cases/:caseId/agent` runs:
1. **Chain planner** classifies the question and produces a single-step or multi-step `AnalysisChainPlan`
2. **Chain path**: if `planKind === "chain"`, `executeChain` runs multiple steps sequentially with parameter binding between steps and graph reload; auto-synthesis appends LLM interpretation if chain has no `llm_explain` step
3. **Deterministic path**: for single-step plans, if a protocol adapter matches (hardcoded regex or learned pattern), it runs tshark queries directly, builds evidence cards and protocol correlations, writes the QueryRun, and returns without calling the LLM agent
4. **Agent fallback**: when no adapter matches (hardcoded or learned), the leader agent handles the query using both case-graph MCP and tshark-query MCP, then triggers async pattern learning for future routing
5. **Agent path**: for open-ended questions (`llm_explain` intent), the leader agent hands off to one of 5 subagents (Triage/Evidence/Path/Protocol/Report)

`POST /api/cases/:caseId/query-runs` runs:
1. Infer or accept time/address/port/protocol filters
2. **tshark-query MCP** builds a display filter
3. **tshark-query MCP** runs `tshark` and returns matching conversations plus bounded packet evidence
4. API builds `AccessCandidateGroup`s, `QueryPath`, and deterministic `QueryDiagnosis`
5. API stores `QueryRun`, selected conversation, path, diagnosis, and evidence cards
6. Browser shows evidence cards and opens packet/conversation/time range evidence through **evidence-opener MCP**

## Protocol Adapter Self-Improvement

Protocol adapter routing follows a three-tier fallback:
1. **Hardcoded regex** — each adapter has built-in match functions
2. **Learned patterns** — `data/learned_patterns.json` stores `{regex, adapterId}` pairs generated by LLM after agent fallback
3. **Agent fallback** — leader agent with tshark-query MCP handles the query; after success, `patternLearner` uses LLM to generate a new regex pattern

The learning module (`src/services/patternLearner.ts`) has no hardcoded tool→adapter mapping. The LLM determines both the regex pattern and the target adapterId from the question context and available adapter list.

## Key Design Constraints

- **Deterministic queries bypass the LLM** — protocol adapters (TCP/DNS/TLS/HTTP/ICMP/UDP) run tshark directly and produce structured evidence cards without agent involvement.
- **Agents read case graph AND can query tshark directly** — the leader agent and subagents have access to both case-graph MCP (read-only case data) and tshark-query MCP (raw packet queries). Protocol agent uses tshark-query tools when deterministic adapters don't match.
- **Upload does not full-parse pcap files** — large-file handling depends on capture metadata first and display-filtered tshark queries later.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The chain planner classifies into single-step or multi-step plans (2-5 steps). Each step uses one of 12 intents. Steps can bind parameters from previous step results via `paramsFrom` JSON path expressions. No hard-coded scenarios — plans are dynamically generated from the case graph.
- The leader agent hands off to exactly one subagent per question. `maxTurns: 8`.
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
- `QueryDiagnosis` runs deterministic checks (handshake completeness, RST, retransmission burst, zero window, bidirectional traffic, FIN close) with thresholds from `config/defaults.json` `api.diagnosis`.
- Graph reload between chain steps ensures subsequent steps can read QueryRuns written by previous steps.
- Auto-synthesis: when a chain has no `llm_explain` step but LLM is configured, routes.ts automatically appends LLM interpretation after chain completes.
- Evidence cards are shown in a new browser tab via Blob URL, not in the chat bubble. Chat is for reading conclusions; the link page is for Wireshark operations.
