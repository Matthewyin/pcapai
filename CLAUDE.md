# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pcapAI is a browser-based packet evidence-chain workbench for offline network troubleshooting. It takes multi-node packet captures with operator context and builds a structured **case graph** (path, session segments, evidence events, findings, packet-level evidence). An OpenAI Agents SDK leader agent with subagents interprets the case graph and answers questions. UI and API text are in Chinese.

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
Zod schemas + TypeScript types for the entire domain model: `CaseSpec`, `CaptureNode`, `MappingHint`, `TimeOffsetHint`, `PacketSummary`, `SessionSegment`, `SessionLink`, `EvidenceEvent`, `Finding`, `PathGraph`, `AnalysisRun`, `CaseGraph`, `AgentAnswer`. All other packages consume these types. API imports shared via a relative path (`../../../../packages/shared/src/index.js`).

### `config/defaults.json` — Central configuration
All runtime defaults live here: API host/port (default `30022`), CORS origins, MCP server launch commands, LLM settings (default: Doubao/ByteDance Ark endpoint), tshark config, and web settings. Every config value can be overridden via `PCAPAI_*` env vars. The API, web Vite config, and MCP servers all resolve the workspace root by walking up to find `config/defaults.json`.

### `apps/api` — Express API + Agent runtime (`@pcapai/api`)
- **`src/config.ts`** — loads defaults from `config/defaults.json` and applies `PCAPAI_*` env overrides. Exports `apiConfig` and `updateLlmConfig()`.
- **`src/index.ts`** — Express app configured from `apiConfig`.
- **`src/http/routes.ts`** — REST endpoints. Key routes:
  - `GET /api/health`
  - `GET/POST /api/settings/llm`, `GET/POST/DELETE /api/settings/llm/profiles`, `POST /api/settings/llm/test` — LLM config CRUD with profile support
  - `POST /api/cases`, `GET /api/cases`, `DELETE /api/cases` — case CRUD, persisted under `data/cases`
  - `POST /api/cases/:caseId/captures` — multer upload with payload trimming via `editcap -s`
  - `PUT /api/cases/:caseId/mapping-hints`, `PUT /api/cases/:caseId/time-offset-hints`
  - `POST /api/cases/:caseId/parse` — calls packet-parser MCP to produce `rawPackets`
  - `POST /api/cases/:caseId/analyze` — full pipeline: filter → normalize → match sessions → build path → generate findings
  - `GET /api/cases/:caseId/report` — Markdown report from case graph
  - `POST /api/cases/:caseId/agent`, `POST /api/cases/:caseId/agent/stream` — SSE streaming agent answers
- **`src/http/caseStore.ts`** — case persistence: `data/cases/:caseId/case.json`, analysis run snapshots in `analysis-runs/`, captures in `captures/`
- **`src/http/capturePreprocess.ts`** — strips packet payload via `editcap -s` before parsing
- **`src/http/llmSettings.ts`** — LLM profile management in `.env` file (profiles stored as `PCAPAI_LLM_PROFILE_*` env vars)
- **`src/mcp/packetParserClient.ts`** — stdio MCP client for packet-parser
- **`src/mcp/packetNormalizerClient.ts`** — stdio MCP client for packet-normalizer
- **`src/mcp/chainBuilderClient.ts`** — stdio MCP client for chain-builder (wraps both `match_cross_node_sessions` and `build_path_graph`)
- **`src/agents/runtime.ts`** — OpenAI Agents SDK runtime. Creates a temp file with case graph JSON, launches `case-graph MCP` via stdio with `PCAPAI_CASE_GRAPH_PATH` env var. Leader agent with 3 handoff subagents (Triage, Evidence, Report), all sharing the same MCP server. Uses `OpenAIProvider` with configurable base URL/model. Falls back to rule-based answer when no LLM key.

### `apps/web` — React workbench (`@pcapai/web`)
Single-file React 19 app (`src/main.tsx`, ~1300 lines). Multi-page layout with workbench, history, settings, and help views. Config (`src/config.ts`) reads `__PCAPAI_WEB_CONFIG__` injected by Vite from `config/defaults.json`. Features:
- Case creation, multi-file pcap upload with per-file metadata (node name, role, direction, position)
- Analysis filter (client/server/port/protocol)
- Mapping hint and time offset hint editing
- Chat-style agent Q&A with SSE streaming
- Detail overlays for path, findings, sessions, links, packets, events
- Analysis run versioning with snapshot restore
- LLM settings management with profile CRUD and connectivity testing
- Dark/light theme toggle

### `mcp/*` — MCP servers
Five stdio-based MCP servers using `@modelcontextprotocol/sdk`:
- **`packet-parser`** — `parse_pcap` calls `tshark -T fields` and returns `PacketSummary[]`. Config via `config/defaults.json` `mcp.packetParser` section.
- **`packet-normalizer`** — `normalize_packets` groups packets by node+5-tuple into `SessionSegment[]`, extracts `EvidenceEvent[]` (SYN/SYN-ACK/RST/ICMP), and builds initial `PathGraph` with suspect edge detection. `validate_capture_context` checks for missing node metadata.
- **`chain-builder`** — `match_cross_node_sessions` scores adjacent capture pairs using protocol/IP/port/time overlap/mapping hints/time offsets. `build_path_graph` constructs path from links. Scoring threshold: 35+.
- **`case-graph`** — Read-only MCP server for agents. Reads case graph from temp file set via `PCAPAI_CASE_GRAPH_PATH`. Tools: `load_case_graph`, `get_finding`, `get_evidence`, `get_session_link`, `get_packet_detail`, `explain_path`, `export_report`.
- **`diagnosis-report`** — `detect_breakpoints`, `export_report` (still stubs).

## Analysis Pipeline

`POST /api/cases/:caseId/analyze` runs:
1. Parse raw packets (if not already cached)
2. Filter packets by analysis filter (client/server/port/protocol)
3. **packet-normalizer MCP**: normalize filtered packets → sessions + evidence + path + findings
4. **chain-builder MCP** `match_cross_node_sessions`: score session pairs → session links
5. **chain-builder MCP** `build_path_graph`: construct path from links
6. Merge link evidence events and generate attributed findings per edge
7. Persist intermediate results (`raw-packets.json`, `packets.json`, `sessions.json`, `session-links.json`)

## Key Design Constraints

- **Agents only read the case graph** — they never parse pcap files, execute shell commands, or modify evidence. Deterministic data processing belongs in MCP servers.
- **No hardcoded business data or environment values in code** — defaults live in `config/defaults.json`, sample data lives in `data/fixtures`.
- **Confidence levels**: `certain`, `high`, `low`, `needs_context`. No evidence = no confident conclusion. Missing observations must state coverage scope.
- The leader agent hands off to exactly one subagent per question. `maxTurns: 8`.
- MCP servers communicate over stdio. API-to-MCP calls go through client wrappers under `apps/api/src/mcp`.
- Case data persists as JSON files under `data/cases/:caseId/`. In-memory `Map<string, CaseGraph>` caches recently loaded graphs.
- LLM profiles are stored as `PCAPAI_LLM_PROFILE_*` entries in `.env`. The active profile is tracked via `PCAPAI_LLM_ACTIVE_PROFILE`.
