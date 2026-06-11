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
    query: {
      candidateGroupLimit: number;
      queryPacketLimit: number;
      conversationPacketLimit: number;
      retainedQueryRunLimit: number;
    };
    preprocess: {
      anomalyPacketLimit: number;
    };
    caseCacheLimit: number;
    rag: {
      rfcDir: string;
      indexPath: string;
      topK: number;
      sectionCharLimit: number;
    };
    diagnosis: {
      shortConversationPacketThreshold: number;
      retransmissionBurstThreshold: number;
      duplicateAckBurstThreshold: number;
      evidencePacketSampleLimit: number;
      transportEvidencePacketSampleLimit: number;
      finEvidencePacketSampleLimit: number;
    };
    pathCorrelation: {
      timeOverlapToleranceSeconds: number;
    };
    planner: {
      fallbackPatterns: {
        usageHelp: string;
        networkStatistics: string;
        selectedSessionDiagnosis: string;
        activeQueryExplain: string;
        reportRequest: string;
        broadTroubleshootingProblem: string;
        concreteTroubleshootingScope: string;
        accessQueryIntent: string;
        accessQueryScope: string;
        captureCorrelation: string;
      };
    };
    tsharkQueryMcp: {
      command: string;
      args: string[];
    };
    evidenceOpenerMcp: {
      command: string;
      args: string[];
    };
  };
  llm: {
    baseURL: string;
    model: string;
    providerData: Record<string, unknown>;
    useResponses: boolean;
    maxTurns: number;
    traceIncludeSensitiveData: boolean;
  };
};

function objectFromJsonEnv(value: string | undefined): Record<string, unknown> {
  if (!value) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    parsed = JSON.parse(value.replace(/\\"/g, "\""));
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("PCAPAI_LLM_PROVIDER_DATA must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

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
  query: {
    candidateGroupLimit: numberFromEnv(process.env.PCAPAI_QUERY_CANDIDATE_GROUP_LIMIT, defaults.api.query.candidateGroupLimit),
    queryPacketLimit: numberFromEnv(process.env.PCAPAI_QUERY_PACKET_LIMIT, defaults.api.query.queryPacketLimit),
    conversationPacketLimit: numberFromEnv(process.env.PCAPAI_CONVERSATION_PACKET_LIMIT, defaults.api.query.conversationPacketLimit),
    retainedQueryRunLimit: numberFromEnv(process.env.PCAPAI_RETAINED_QUERY_RUN_LIMIT, defaults.api.query.retainedQueryRunLimit)
  },
  preprocess: {
    anomalyPacketLimit: numberFromEnv(process.env.PCAPAI_PREPROCESS_ANOMALY_PACKET_LIMIT, defaults.api.preprocess.anomalyPacketLimit)
  },
  caseCacheLimit: numberFromEnv(process.env.PCAPAI_CASE_CACHE_LIMIT, defaults.api.caseCacheLimit),
  rag: {
    rfcDir: process.env.PCAPAI_RAG_RFC_DIR
      ? path.resolve(process.env.PCAPAI_RAG_RFC_DIR)
      : path.resolve(workspaceRoot, defaults.api.rag.rfcDir),
    indexPath: process.env.PCAPAI_RAG_INDEX_PATH
      ? path.resolve(process.env.PCAPAI_RAG_INDEX_PATH)
      : path.resolve(workspaceRoot, defaults.api.rag.indexPath),
    topK: numberFromEnv(process.env.PCAPAI_RAG_TOP_K, defaults.api.rag.topK),
    sectionCharLimit: numberFromEnv(process.env.PCAPAI_RAG_SECTION_CHAR_LIMIT, defaults.api.rag.sectionCharLimit)
  },
  diagnosis: {
    shortConversationPacketThreshold: numberFromEnv(process.env.PCAPAI_SHORT_CONVERSATION_PACKET_THRESHOLD, defaults.api.diagnosis.shortConversationPacketThreshold),
    retransmissionBurstThreshold: numberFromEnv(process.env.PCAPAI_RETRANSMISSION_BURST_THRESHOLD, defaults.api.diagnosis.retransmissionBurstThreshold),
    duplicateAckBurstThreshold: numberFromEnv(process.env.PCAPAI_DUPLICATE_ACK_BURST_THRESHOLD, defaults.api.diagnosis.duplicateAckBurstThreshold),
    evidencePacketSampleLimit: numberFromEnv(process.env.PCAPAI_EVIDENCE_PACKET_SAMPLE_LIMIT, defaults.api.diagnosis.evidencePacketSampleLimit),
    transportEvidencePacketSampleLimit: numberFromEnv(process.env.PCAPAI_TRANSPORT_EVIDENCE_PACKET_SAMPLE_LIMIT, defaults.api.diagnosis.transportEvidencePacketSampleLimit),
    finEvidencePacketSampleLimit: numberFromEnv(process.env.PCAPAI_FIN_EVIDENCE_PACKET_SAMPLE_LIMIT, defaults.api.diagnosis.finEvidencePacketSampleLimit)
  },
  pathCorrelation: {
    timeOverlapToleranceSeconds: numberFromEnv(process.env.PCAPAI_PATH_TIME_OVERLAP_TOLERANCE_SECONDS, defaults.api.pathCorrelation.timeOverlapToleranceSeconds)
  },
  planner: {
    fallbackPatterns: {
      ...defaults.api.planner.fallbackPatterns,
      ...objectFromJsonEnv(process.env.PCAPAI_PLANNER_FALLBACK_PATTERNS)
    }
  },
  tsharkQueryMcp: {
    command: process.env.PCAPAI_TSHARK_QUERY_MCP_COMMAND || defaults.api.tsharkQueryMcp.command,
    args: process.env.PCAPAI_TSHARK_QUERY_MCP_ARGS
      ? process.env.PCAPAI_TSHARK_QUERY_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.tsharkQueryMcp.args,
    cwd: workspaceRoot
  },
  evidenceOpenerMcp: {
    command: process.env.PCAPAI_EVIDENCE_OPENER_MCP_COMMAND || defaults.api.evidenceOpenerMcp.command,
    args: process.env.PCAPAI_EVIDENCE_OPENER_MCP_ARGS
      ? process.env.PCAPAI_EVIDENCE_OPENER_MCP_ARGS.split(" ").filter(Boolean)
      : defaults.api.evidenceOpenerMcp.args,
    cwd: workspaceRoot
  },
  llm: {
    apiKey: process.env.PCAPAI_LLM_API_KEY || process.env.OPENAI_API_KEY || "",
    baseURL: process.env.PCAPAI_LLM_BASE_URL || process.env.OPENAI_BASE_URL || defaults.llm.baseURL,
    model: process.env.PCAPAI_LLM_MODEL || defaults.llm.model,
    providerData: objectFromJsonEnv(process.env.PCAPAI_LLM_PROVIDER_DATA),
    useResponses: process.env.PCAPAI_LLM_USE_RESPONSES
      ? process.env.PCAPAI_LLM_USE_RESPONSES === "true"
      : defaults.llm.useResponses,
    maxTurns: numberFromEnv(process.env.PCAPAI_LLM_MAX_TURNS, defaults.llm.maxTurns),
    traceIncludeSensitiveData: process.env.PCAPAI_TRACE_INCLUDE_SENSITIVE_DATA
      ? process.env.PCAPAI_TRACE_INCLUDE_SENSITIVE_DATA === "true"
      : defaults.llm.traceIncludeSensitiveData
  }
};

export function updateLlmConfig(input: { apiKey?: string; baseURL?: string; model?: string; providerData?: Record<string, unknown> }) {
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
  if (input.providerData !== undefined) {
    apiConfig.llm.providerData = input.providerData;
    process.env.PCAPAI_LLM_PROVIDER_DATA = JSON.stringify(input.providerData);
  }
}
