# pcapAI

Agent-first packet troubleshooting chat workbench. Upload pcap files, ask questions in natural language, get deterministic evidence cards with one-click Wireshark drill-down.

## How it works

```
User uploads pcap + asks question
  → Chain Planner classifies intent, produces single-step or multi-step plan
  → Deterministic protocol adapters run tshark queries (TCP/DNS/TLS/HTTP/ICMP/UDP)
  → Three-tier routing: hardcoded regex → learned patterns → agent with tshark-query MCP
  → Evidence cards shown in new browser tab, text analysis in chat bubble
  → Agent explains findings and suggests follow-up queries
  → User clicks any card → local Wireshark opens with the exact filter
```

Chain Planner generates 1–5 step plans dynamically. Each step uses one of 12 intents. Steps can bind parameters from prior results via JSON path expressions. No scenario is hard-coded — plans derive from the case graph.

Protocol adapters self-improve: when no regex matches, the agent handles the query via tshark-query MCP and LLM generates a new regex pattern for future routing.

## Quick start

```bash
npm install
npm run dev          # starts API (port 30022) + web (port 30023)
```

Open `http://127.0.0.1:30023`. Default config lives in `config/defaults.json`, overridable via `PCAPAI_*` env vars.

To enable LLM-powered agent and chain planner:

```bash
cp .env.example .env
# edit PCAPAI_LLM_API_KEY in .env
```

Without an API key, the system falls back to local pattern matching for intent classification and skips the agent conversation path. Deterministic protocol adapters always work.

## Architecture

```
apps/web         React 19 single-file workbench — chat, evidence cards, settings
apps/api         Express API + chain planner + deterministic adapters + agent runtime
mcp/tshark-query capinfos + tshark queries (conversations, packets, protocols, stats)
mcp/evidence-opener  opens local Wireshark with pcap path + display filter
mcp/case-graph   read-only MCP for agents — loads case graph from temp file
packages/shared  Zod schemas + TypeScript types for the full domain model
```

### Request pipeline

```
POST /agent/stream
  planChain()         → single-step or multi-step AnalysisChainPlan
  executeChain()      → runs steps sequentially, binds params between steps
  per step:
    deterministic?    → protocol adapter three-tier routing:
                         hardcoded regex → learned patterns → agent fallback
    open-ended?       → leader agent hands off to Triage/Evidence/Path/Protocol/Report subagents
  aggregate result    → AgentAnswer with evidence cards, checks, suggested queries
```

### Deterministic protocol adapters

| Adapter | Triggers on | Checks produced |
|---------|-------------|-----------------|
| TCP | RST, retransmission, zero-window, SYN, one-way traffic | Session pair health |
| DNS | DNS queries, NXDOMAIN, SERVFAIL | Rcode distribution, unanswered queries |
| TLS | ClientHello, ServerHello, alerts, SNI | Handshake status, SNI distribution, version mix |
| HTTP | Status codes, request/response pairing | Status distribution, latency outliers, host distribution |
| ICMP | Unreachable, TTL exceeded, fragmentation | Error event summary |
| UDP | Flow aggregation by endpoint pair | Flow distribution |

Each adapter builds evidence cards and L7-to-TCP protocol correlations without LLM involvement.

### Protocol adapter self-improvement

When no hardcoded regex matches a question:
1. Check learned patterns from `data/learned_patterns.json`
2. If still no match, fall back to agent (with tshark-query MCP access)
3. After agent handles the query, LLM generates a new regex pattern + target adapterId
4. Pattern is validated and persisted for future deterministic routing

No hardcoded tool→adapter mapping — LLM determines both regex and adapterId.

### Agent architecture

Leader agent with 5 handoff subagents (Triage, Evidence, Path, Protocol, Report), all sharing case-graph MCP and tshark-query MCP. Agents can query raw packet data via tshark-query tools but never parse pcap files or execute shell commands. They can suggest follow-up queries via `suggest_next_query`, but the user decides whether to execute them.

## Commands

```bash
npm run dev                # API + web
npm run dev -w apps/api    # API only
npm run dev -w apps/web    # web only
npm run build              # build all workspaces
npm run check              # type-check all workspaces
npm run test               # run tests (apps/api + mcp/tshark-query)
```

## Documentation

- [Design document](docs/design.md) — scope, data model, analysis principles, self-improvement
- [Architecture](docs/architecture.md) — QueryRun pipeline, agent boundaries, three-tier adapter routing

## Tech stack

- TypeScript, React 19, Express, Vite
- OpenAI Agents SDK (pluggable LLM endpoint via config)
- MCP (Model Context Protocol) over stdio
- tshark / Wireshark for packet analysis
- npm workspaces monorepo
