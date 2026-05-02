# pcapAI

pcapAI is an Agent-first packet troubleshooting chat workbench built around OpenAI Agents SDK for TypeScript.

## Architecture

- Browser workbench: `apps/web`
- Agent API: `apps/api`
- Leader agent and subagents: `apps/api/src/agents`
- MCP servers:
  - `mcp/tshark-query`
  - `mcp/evidence-opener`
  - `mcp/case-graph`
- Shared schemas: `packages/shared`

Detailed docs:

- [首版设计方案](docs/design.md)
- [Agent 与 MCP 架构](docs/architecture.md)

## Development

```bash
npm install
npm run dev
```

Open the Vite URL printed by `npm run dev`.

Default local settings live in `config/defaults.json` and can be overridden with environment variables.

To enable real LLM calls, set `PCAPAI_LLM_API_KEY`. See `.env.example`.

## Boundary

The main troubleshooting unit is a chat-scoped `QueryRun`: user question and uploaded pcap -> capture metadata -> tshark display filter -> candidate conversations -> evidence cards -> Wireshark opener. Upload does not full-parse large pcap files; packet summaries are read later through bounded, display-filtered tshark queries. Agents explain active QueryRun evidence, route questions, ask for missing context, and prepare user-facing output.
