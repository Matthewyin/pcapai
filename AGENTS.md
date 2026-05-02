# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

pcapAI is an Agent-first packet troubleshooting chat workbench. Its primary unit is a **QueryRun** inside a chat session: uploaded pcap + user question -> tshark display filter -> candidate conversations -> evidence cards -> Wireshark opener. An OpenAI Agents SDK leader agent with subagents interprets the active QueryRun and case graph. UI and API text are in Chinese.

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

## Architecture

npm workspace monorepo with three workspace groups:

### `packages/shared` — Shared schemas (`@pcapai/shared`)
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `Conversation`, `QueryRun`, `QueryPath`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: Doubao/ByteDance Ark endpoint), tshark config, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

### `apps/api` — Express API + Agent runtime (`@pcapai/api`)
- **`src/config.ts`** — loads defaults from `config/defaults.json` and applies `PCAPAI_*` env overrides. Exports `apiConfig` and `updateLlmConfig()`.
- **`src/index.ts`** — Express app configured from `apiConfig`.
- **`src/http/routes.ts`** — REST endpoints. Key routes:
  - `GET /api/health`
  - `GET/POST /api/settings/llm`, `GET/POST/DELETE /api/settings/llm/profiles`, `POST /api/settings/llm/test` — LLM config CRUD with profile support
  - `POST /api/cases`, `POST /api/cases/new-chat`, `GET /api/cases`, `DELETE /api/cases` — case/session CRUD, persisted under `data/cases`
  - `POST /api/cases/:caseId/attachments` — chat composer pcap upload with payload trimming via `editcap -s`; stores capture metadata and capinfos time range, without full packet-summary parsing
  - `PUT /api/cases/:caseId/mapping-hints`, `PUT /api/cases/:caseId/time-offset-hints`
  - `POST /api/cases/:caseId/query-runs` — creates a QueryRun from user question and optional structured filters
  - `GET /api/cases/:caseId/query-runs/:queryRunId`
  - `POST /api/cases/:caseId/query-runs/:queryRunId/conversations/:conversationId/select`
  - `POST /api/cases/:caseId/query-runs/:queryRunId/open-wireshark`
  - `POST /api/cases/:caseId/evidence/open` — opens pcap evidence in local Wireshark via evidence-opener MCP
  - `GET /api/cases/:caseId/report` — Markdown report from case graph
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/mcp/tsharkQueryClient.ts`** — stdio MCP client for tshark-query
- **`src/mcp/evidenceOpenerClient.ts`** — stdio MCP client for evidence-opener
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime. Creates a temp file with case graph JSON, launches `case-graph MCP` via stdio with `PCAPAI_CASE_GRAPH_PATH` env var. Leader agent with 3 handoff subagents (Triage, Evidence, Report), all sharing the same MCP server. Uses `OpenAIProvider` with configurable base URL/model. Falls back to rule-based answer when no LLM key.

### `apps/web` — React workbench (`@pcapai/web`)
Single-file React 19 app (`src/main.tsx`). Chat-first layout with session history, central message stream, bottom composer, settings, and help views. Config (`src/config.ts`) reads `__PCAPAI_WEB_CONFIG__` injected by Vite from `config/defaults.json`. Features:
- New chat creates an empty case
- Composer pcap upload via file picker, drag/drop, and paste
- QueryRun-driven evidence cards for filters, conversations, packets, and time ranges
- Mapping hint and time offset hint editing
- Chat-style agent Q&A with SSE streaming
- LLM settings management with profile CRUD and connectivity testing
- Dark/light theme toggle

### `mcp/*` — MCP servers
Three stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`tshark-query`** — reads capture metadata with `capinfos`, builds display filters, and runs `tshark` for conversations, packet queries, packet details, TCP resets, retransmissions, and zero-window events.
- **`evidence-opener`** — opens local Wireshark for a pcap path and display filter. It does not analyze packets.
- **`case-graph`** — Read-only MCP server for agents. Reads case graph from temp file set via `PCAPAI_CASE_GRAPH_PATH`. Tools include `load_case_graph`, `get_case_statistics`, `get_active_query_run`, `get_query_run`, `get_conversation`, `get_packet_detail`, `explain_path`, `export_report`.

## Analysis Pipeline

`POST /api/cases/:caseId/query-runs` runs:
1. Infer or accept time/address/port/protocol filters
2. **tshark-query MCP** builds a display filter
3. **tshark-query MCP** runs `tshark` and returns matching conversations plus bounded packet evidence
4. API stores `QueryRun`, selected conversation, `QueryPath`, and evidence cards
5. Browser shows evidence cards and opens packet/conversation/time range evidence through **evidence-opener MCP**
6. Agent explains the active QueryRun through `case-graph MCP`

## Key Design Constraints

- **Agents only read the case graph** — they never parse pcap files, execute shell commands, or modify evidence. Deterministic data processing belongs in MCP servers.
- **Upload does not full-parse pcap files** — large-file handling depends on capture metadata first and display-filtered tshark queries later.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The leader agent hands off to exactly one subagent per question. `maxTurns: 8`.
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
