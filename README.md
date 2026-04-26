# pcapAI

pcapAI is a browser-based packet evidence-chain workbench built around OpenAI Agents SDK for TypeScript.

## Architecture

- Browser workbench: `apps/web`
- Agent API: `apps/api`
- Leader agent and subagents: `apps/api/src/agents`
- MCP servers:
  - `mcp/packet-parser`
  - `mcp/packet-normalizer`
  - `mcp/chain-builder`
  - `mcp/diagnosis-report`
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

The leader agent coordinates subagents and MCP tools. MCP servers perform deterministic packet parsing, normalization, chain building, and report preparation. Agents explain, route, ask for missing context, and prepare user-facing output.
