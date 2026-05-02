# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcapAI is an Agent-first packet troubleshooting chat workbench. Its primary unit is a **QueryRun** inside a chat session: uploaded pcap + user question -> intent classification -> deterministic protocol query or agent conversation -> evidence cards -> Wireshark opener. An OpenAI Agents SDK intent planner classifies questions, deterministic protocol adapters handle structured queries (TCP metrics, DNS, TLS, HTTP, ICMP, UDP), and a leader agent with subagents handles open-ended analysis. UI and API text are in Chinese.

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
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `Conversation`, `QueryRun`, `QueryPath`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`, `QueryDiagnosis`, `ProtocolCorrelation`, `EvidenceCard`, `AccessCandidateGroup`, `ToolRun`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: Doubao/ByteDance Ark endpoint), tshark config, query limits, diagnosis thresholds, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

### `apps/api` — Express API + Agent runtime (`@pcapai/api`)
- **`src/config.ts`** — loads defaults from `config/defaults.json` and applies `PCAPAI_*` env overrides. Exports `apiConfig` and `updateLlmConfig()`.
- **`src/index.ts`** — Express app configured from `apiConfig`.
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
  - `POST /api/cases/:caseId/evidence/open` — opens pcap evidence in local Wireshark via evidence-opener MCP
  - `GET /api/cases/:caseId/report` — Markdown report from case graph via `reportBuilder.ts`
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/reportBuilder.ts`** — generates structured Markdown report from case graph: sections for query, data sources, evidence, L7 correlations, access objects, multi-node path, diagnosis checks, and Wireshark filters
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/protocolAdapters/`** — deterministic protocol-specific query subsystem:
  - `types.ts` — `ProtocolAdapter` interface and `runProtocolAdapter()` dispatcher; adapters match by regex on user question and run tshark queries
  - `builders.ts` — shared logic: packet pair grouping, evidence card creation, `QueryRun` construction, L7-to-TCP protocol correlations (DNS→TCP, TLS SNI→TCP, HTTP Host→TCP)
  - `tcp.ts` — RST session pairs, retransmission pairs, zero-window pairs, SYN-no-SYN/ACK pairs, one-way traffic pairs
  - `dns.ts` — DNS failure/unresponsive transactions with rcode grouping
  - `tls.ts` — TLS handshake events (ClientHello, ServerHello, alerts) with handshake completeness checks
  - `http.ts` — HTTP transactions with status code filtering (4xx/5xx) and request/response matching
  - `icmp.ts` — ICMP unreachable/TTL exceeded/fragmentation events
  - `udp.ts` — UDP flow aggregation by endpoint pair
- **`src/mcp/tsharkQueryClient.ts`** — stdio MCP client for tshark-query; wraps 15 tool calls (build_display_filter, get_capture_time_range, list_protocols, get_network_statistics, list_tcp_conversations, query_packets, list_tcp_resets, list_tcp_retransmissions, list_tcp_zero_window, list_icmp_events, list_dns_packets, list_udp_packets, list_tls_packets, list_http_packets, get_conversation_packets)
- **`src/mcp/evidenceOpenerClient.ts`** — stdio MCP client for evidence-opener
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime with three phases:
  1. **Intent planner** (`runIntentPlanner`) — classifies question into one of 12 intents (usage_help, protocol_statistics, network_statistics, tcp_session_query, protocol_event_query, capture_correlation, mapping_hint_update, active_query_explain, selected_session_diagnosis, report_request, needs_clarification, llm_explain)
  2. **Deterministic handlers** — protocol adapters and route-level handlers handle structured queries without LLM
  3. **Agent conversation** (`runPcapTroubleshootingAgent`) — creates temp file with case graph JSON, launches `case-graph MCP` via stdio with `PCAPAI_CASE_GRAPH_PATH` env var. Leader agent with 3 handoff subagents (Triage, Evidence, Report), all sharing the same MCP server. Uses `OpenAIProvider` with configurable base URL/model. `maxTurns: 8`.

### `apps/web` — React workbench (`@pcapai/web`)
Single-file React 19 app (`src/main.tsx`). Chat-first layout with session history, central message stream, bottom composer, settings, and help views. Config (`src/config.ts`) reads `__PCAPAI_WEB_CONFIG__` injected by Vite from `config/defaults.json`. Features:
- New chat creates an empty case
- Composer pcap upload via file picker, drag/drop, and paste
- QueryRun-driven evidence cards for filters, conversations, packets, protocol correlations, and time ranges
- Mapping hint and time offset hint editing
- Chat-style agent Q&A with SSE streaming
- LLM settings management with profile CRUD and connectivity testing
- Dark/light theme toggle

### `mcp/*` — MCP servers
Three stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`tshark-query`** — reads capture metadata with `capinfos`, builds display filters, and runs `tshark` for conversations, packet queries, packet details, TCP resets/retransmissions/zero-window, ICMP events, DNS packets, UDP flows, TLS events, HTTP packets, protocol listing, and network statistics. 15 tools.
- **`evidence-opener`** — opens local Wireshark for a pcap path and display filter. It does not analyze packets.
- **`case-graph`** — Read-only MCP server for agents. Reads case graph from temp file set via `PCAPAI_CASE_GRAPH_PATH`. Tools: `load_case_graph`, `get_case_statistics`, `get_finding`, `get_evidence`, `get_session_link`, `get_packet_detail`, `explain_path`, `export_report`.

## Query Pipeline

`POST /api/cases/:caseId/agent` runs:
1. **Intent planner** classifies the question (protocol-specific, session diagnosis, report, help, or open-ended)
2. **Deterministic path**: if a protocol adapter matches, it runs tshark queries directly, builds evidence cards and protocol correlations, writes the QueryRun, and returns without calling the LLM agent
3. **Agent path**: for open-ended questions, the leader agent hands off to Triage/Evidence/Report subagents via case-graph MCP

`POST /api/cases/:caseId/query-runs` runs:
1. Infer or accept time/address/port/protocol filters
2. **tshark-query MCP** builds a display filter
3. **tshark-query MCP** runs `tshark` and returns matching conversations plus bounded packet evidence
4. API builds `AccessCandidateGroup`s, `QueryPath`, and deterministic `QueryDiagnosis` (handshake, RST, retransmission, zero-window, traffic direction, FIN close checks)
5. API stores `QueryRun`, selected conversation, path, diagnosis, and evidence cards
6. Browser shows evidence cards and opens packet/conversation/time range evidence through **evidence-opener MCP**

## Key Design Constraints

- **Deterministic queries bypass the LLM** — protocol adapters (TCP metrics, DNS, TLS, HTTP, ICMP, UDP) run tshark directly and produce structured evidence cards without agent involvement.
- **Agents only read the case graph** — they never parse pcap files, execute shell commands, or modify evidence. Deterministic data processing belongs in MCP servers and protocol adapters.
- **Upload does not full-parse pcap files** — large-file handling depends on capture metadata first and display-filtered tshark queries later.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The intent planner classifies into 12 intents. The leader agent hands off to exactly one subagent per question. `maxTurns: 8`.
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
- `QueryDiagnosis` runs deterministic checks (handshake completeness, RST, retransmission burst, zero window, bidirectional traffic, FIN close) with thresholds from `config/defaults.json` `api.diagnosis`.
