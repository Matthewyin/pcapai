import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { config as loadDotenv } from "dotenv";

function numberFromEnv(value: string | undefined, fallback: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function listFromEnv(value: string | undefined, fallback: string[]) {
  if (!value) return fallback;
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function resolveWorkspaceRoot() {
  const candidates = [
    process.env.PCAPAI_ROOT ? path.resolve(process.env.PCAPAI_ROOT) : "",
    process.cwd(),
    path.resolve(process.cwd(), "../..")
  ].filter(Boolean);

  return candidates.find((candidate) => existsSync(path.join(candidate, "config/defaults.json"))) || process.cwd();
}

const workspaceRoot = resolveWorkspaceRoot();
loadDotenv({ path: path.join(workspaceRoot, ".env"), override: false });

const configPath = process.env.PCAPAI_CONFIG_PATH
  ? path.resolve(process.env.PCAPAI_CONFIG_PATH)
  : path.join(workspaceRoot, "config/defaults.json");

const defaults = JSON.parse(readFileSync(configPath, "utf8")) as {
  api: {
    host: string;
    port: number;
    corsOrigins: string[];
    jsonLimit: string;
    caseDataDir: string;
    uploadFieldName: string;
    payloadTrim: {
      enabled: boolean;
      editcapCommand: string;
      snaplen: number;
    };
    packetParserMcp: {
      command: string;
      args: string[];
    };
    packetNormalizerMcp: {
      command: string;
      args: string[];
    };
    chainBuilderMcp: {
      command: string;
      args: string[];
    };
    caseGraphMcp: {
      command: string;
      args: string[];
    };
  };
  llm: {
    baseURL: string;
    model: string;
    useResponses: boolean;
    traceIncludeSensitiveData: boolean;
  };
};

export const apiConfig = {
  host: process.env.PCAPAI_API_HOST || defaults.api.host,
  port: numberFromEnv(process.env.PCAPAI_API_PORT || process.env.PORT, defaults.api.port),
  corsOrigins: listFromEnv(process.env.PCAPAI_CORS_ORIGINS, defaults.api.corsOrigins),
  jsonLimit: process.env.PCAPAI_JSON_LIMIT || defaults.api.jsonLimit,
  caseDataDir: process.env.PCAPAI_CASE_DATA_DIR
    ? path.resolve(process.env.PCAPAI_CASE_DATA_DIR)
    : path.resolve(workspaceRoot, defaults.api.caseDataDir),
  uploadFieldName: process.env.PCAPAI_UPLOAD_FIELD_NAME || defaults.api.uploadFieldName,
  payloadTrim: {
    enabled: process.env.PCAPAI_PAYLOAD_TRIM_ENABLED
      ? process.env.PCAPAI_PAYLOAD_TRIM_ENABLED === "true"
      : defaults.api.payloadTrim.enabled,
    editcapCommand: process.env.PCAPAI_EDITCAP_COMMAND || defaults.api.payloadTrim.editcapCommand,
    snaplen: numberFromEnv(process.env.PCAPAI_PAYLOAD_TRIM_SNAPLEN, defaults.api.payloadTrim.snaplen)
  },
  packetParserMcp: {
    command: process.env.PCAPAI_PACKET_PARSER_MCP_COMMAND || defaults.api.packetParserMcp.command,
    args: process.env.PCAPAI_PACKET_PARSER_MCP_ARGS
      ? process.env.PCAPAI_PACKET_PARSER_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.packetParserMcp.args,
    cwd: workspaceRoot
  },
  packetNormalizerMcp: {
    command: process.env.PCAPAI_PACKET_NORMALIZER_MCP_COMMAND || defaults.api.packetNormalizerMcp.command,
    args: process.env.PCAPAI_PACKET_NORMALIZER_MCP_ARGS
      ? process.env.PCAPAI_PACKET_NORMALIZER_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.packetNormalizerMcp.args,
    cwd: workspaceRoot
  },
  chainBuilderMcp: {
    command: process.env.PCAPAI_CHAIN_BUILDER_MCP_COMMAND || defaults.api.chainBuilderMcp.command,
    args: process.env.PCAPAI_CHAIN_BUILDER_MCP_ARGS
      ? process.env.PCAPAI_CHAIN_BUILDER_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.chainBuilderMcp.args,
    cwd: workspaceRoot
  },
  caseGraphMcp: {
    command: process.env.PCAPAI_CASE_GRAPH_MCP_COMMAND || defaults.api.caseGraphMcp.command,
    args: process.env.PCAPAI_CASE_GRAPH_MCP_ARGS
      ? process.env.PCAPAI_CASE_GRAPH_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.caseGraphMcp.args,
    cwd: workspaceRoot
  },
  llm: {
    apiKey: process.env.PCAPAI_LLM_API_KEY || process.env.OPENAI_API_KEY || "",
    baseURL: process.env.PCAPAI_LLM_BASE_URL || process.env.OPENAI_BASE_URL || defaults.llm.baseURL,
    model: process.env.PCAPAI_LLM_MODEL || defaults.llm.model,
    useResponses: process.env.PCAPAI_LLM_USE_RESPONSES
      ? process.env.PCAPAI_LLM_USE_RESPONSES === "true"
      : defaults.llm.useResponses,
    traceIncludeSensitiveData: process.env.PCAPAI_TRACE_INCLUDE_SENSITIVE_DATA
      ? process.env.PCAPAI_TRACE_INCLUDE_SENSITIVE_DATA === "true"
      : defaults.llm.traceIncludeSensitiveData
  }
};

export function updateLlmConfig(input: { apiKey?: string; baseURL?: string; model?: string }) {
  if (input.apiKey !== undefined) {
    apiConfig.llm.apiKey = input.apiKey;
    process.env.PCAPAI_LLM_API_KEY = input.apiKey;
  }
  if (input.baseURL !== undefined) {
    apiConfig.llm.baseURL = input.baseURL;
    process.env.PCAPAI_LLM_BASE_URL = input.baseURL;
  }
  if (input.model !== undefined) {
    apiConfig.llm.model = input.model;
    process.env.PCAPAI_LLM_MODEL = input.model;
  }
}
