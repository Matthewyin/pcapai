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
      /** 完整库路径（userData 内静默下载，750MB，双层库上层） */
      indexPath: string;
      /** 精简库路径（Resources 内置，~20MB，双层库降级层） */
      curatedIndexPath: string;
      topK: number;
      sectionCharLimit: number;
      /** 完整库下载配置（GitHub Release 静默下载） */
      download: {
        /** 下载源 URL（GitHub Release 资产直链） */
        url: string;
        /** 下载到 userData 的目标文件名 */
        targetFilename: string;
        /** 断点续传分片大小（字节，默认 1MB） */
        chunkSize: number;
        /** 下载超时（毫秒，默认 5 分钟） */
        timeoutMs: number;
      };
    };
    fieldNotes: {
      seedsDir: string;
      indexPath: string;
      topK: number;
      scores: {
        missingFlag: number;
        analysisFlag: number;
        observedFlag: number;
      };
    };
    skills: {
      dir: string;
      /** 额外 skills 目录（多目录注册制，用户可配置外部/团队目录） */
      extraDirs: string[];
    };
    session: {
      compressThreshold: number;
      keepRecent: number;
      maxToolResultChars: number;
      maxDialogueChars: number;
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
      learnedBypassMinHits: number;
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
    /** MCP server 注册表（替代旧的 tsharkQueryMcp/evidenceOpenerMcp 硬编码） */
    mcpServers: {
      id: string;
      name: string;
      type: "local" | "sse" | "streamable-http";
      enabled: boolean;
      builtIn: boolean;
      command?: string;
      args?: string[];
      env?: Record<string, string>;
      url?: string;
    }[];
    /** 向后兼容：旧版 tsharkQueryMcp/evidenceOpenerMcp（已被 mcpServers 替代，保留用于 seed） */
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
    temperature?: number;
    maxTokens?: number;
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
  // 本地自用：API 进程同源托管前端静态产物（前端与 /api 同端口，相对路径无断裂）
  serveWeb: process.env.PCAPAI_SERVE_WEB === "1",
  webDistPath: process.env.PCAPAI_WEB_DIST_PATH
    ? path.resolve(process.env.PCAPAI_WEB_DIST_PATH)
    : path.resolve(workspaceRoot, "apps/web/dist"),
  learnedPatternsPath: process.env.PCAPAI_LEARNED_PATTERNS_PATH
    ? path.resolve(process.env.PCAPAI_LEARNED_PATTERNS_PATH)
    : path.resolve(workspaceRoot, "data/learned_patterns.json"),
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
    curatedIndexPath: process.env.PCAPAI_RAG_CURATED_INDEX_PATH
      ? path.resolve(process.env.PCAPAI_RAG_CURATED_INDEX_PATH)
      : path.resolve(workspaceRoot, defaults.api.rag.curatedIndexPath),
    topK: numberFromEnv(process.env.PCAPAI_RAG_TOP_K, defaults.api.rag.topK),
    sectionCharLimit: numberFromEnv(process.env.PCAPAI_RAG_SECTION_CHAR_LIMIT, defaults.api.rag.sectionCharLimit),
    download: {
      url: process.env.PCAPAI_RAG_DOWNLOAD_URL ?? defaults.api.rag.download.url,
      targetFilename: defaults.api.rag.download.targetFilename,
      chunkSize: numberFromEnv(process.env.PCAPAI_RAG_DOWNLOAD_CHUNK_SIZE, defaults.api.rag.download.chunkSize),
      timeoutMs: numberFromEnv(process.env.PCAPAI_RAG_DOWNLOAD_TIMEOUT_MS, defaults.api.rag.download.timeoutMs)
    }
  },
  fieldNotes: {
    seedsDir: process.env.PCAPAI_FIELD_NOTES_SEEDS_DIR
      ? path.resolve(process.env.PCAPAI_FIELD_NOTES_SEEDS_DIR)
      : path.resolve(workspaceRoot, defaults.api.fieldNotes.seedsDir),
    indexPath: process.env.PCAPAI_FIELD_NOTES_INDEX_PATH
      ? path.resolve(process.env.PCAPAI_FIELD_NOTES_INDEX_PATH)
      : path.resolve(workspaceRoot, defaults.api.fieldNotes.indexPath),
    topK: numberFromEnv(process.env.PCAPAI_FIELD_NOTES_TOP_K, defaults.api.fieldNotes.topK),
    scores: defaults.api.fieldNotes.scores
  },
  skills: {
    dir: process.env.PCAPAI_SKILLS_DIR
      ? path.resolve(process.env.PCAPAI_SKILLS_DIR)
      : path.resolve(workspaceRoot, defaults.api.skills.dir),
    /** 额外 skills 目录（用户可配置外部目录，逗号分隔的环境变量或 defaults extraDirs） */
    extraDirs: resolveSkillsExtraDirs(defaults.api.skills.extraDirs || [])
  },
  session: {
    compressThreshold: numberFromEnv(process.env.PCAPAI_SESSION_COMPRESS_THRESHOLD, defaults.api.session.compressThreshold),
    keepRecent: numberFromEnv(process.env.PCAPAI_SESSION_KEEP_RECENT, defaults.api.session.keepRecent),
    maxToolResultChars: numberFromEnv(process.env.PCAPAI_SESSION_MAX_TOOL_RESULT_CHARS, defaults.api.session.maxToolResultChars),
    maxDialogueChars: numberFromEnv(process.env.PCAPAI_SESSION_MAX_DIALOGUE_CHARS, defaults.api.session.maxDialogueChars)
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
    learnedBypassMinHits: numberFromEnv(process.env.PCAPAI_PLANNER_LEARNED_BYPASS_MIN_HITS, defaults.api.planner.learnedBypassMinHits),
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
  /** MCP server 注册表：支持 local(stdio)/sse/streamable-http 三种类型。
   *  环境变量 PCAPAI_TSHARK_QUERY_MCP_* / PCAPAI_EVIDENCE_OPENER_MCP_* 会覆盖内置 server 配置（dev 模式优先）。
   *  userData 的 mcp-registries.json 会覆盖 defaults（用户可编辑，设置页可视化操作）。 */
  mcpServers: resolveMcpServers(defaults.api.mcpServers || []),
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
      : defaults.llm.traceIncludeSensitiveData,
    temperature: process.env.PCAPAI_LLM_TEMPERATURE ? Number(process.env.PCAPAI_LLM_TEMPERATURE) || undefined : undefined,
    maxTokens: process.env.PCAPAI_LLM_MAX_TOKENS ? Number(process.env.PCAPAI_LLM_MAX_TOKENS) || undefined : undefined
  }
};

export function updateLlmConfig(input: { apiKey?: string; baseURL?: string; model?: string; providerData?: Record<string, unknown>; temperature?: number; maxTokens?: number }) {
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
  // temperature/maxTokens：undefined 表示该 profile 没配（清除旧值），需显式赋 undefined 而非跳过，
  // 否则从「配了 temperature 的 profile」切到「没配的 profile」时旧值会残留。
  if ("temperature" in input) {
    apiConfig.llm.temperature = input.temperature;
    process.env.PCAPAI_LLM_TEMPERATURE = input.temperature !== undefined ? String(input.temperature) : "";
  }
  if ("maxTokens" in input) {
    apiConfig.llm.maxTokens = input.maxTokens;
    process.env.PCAPAI_LLM_MAX_TOKENS = input.maxTokens !== undefined ? String(input.maxTokens) : "";
  }
}

/**
 * 路径变量替换：把 ${resources}/${userData}/${workspace} 替换为实际路径。
 * 打包后 resources=process.resourcesPath/app, userData=PCAPAI_USERDATA_DIR, workspace=PCAPAI_ROOT
 */
export function resolvePathVars(p: string): string {
  const resources = process.env.PCAPAI_ROOT || (typeof (process as unknown as { resourcesPath?: string }).resourcesPath === "string" ? path.join((process as unknown as { resourcesPath: string }).resourcesPath, "app") : workspaceRoot);
  const userData = process.env.PCAPAI_USERDATA_DIR || workspaceRoot;
  return p
    .replace(/\$\{resources\}/g, resources)
    .replace(/\$\{userData\}/g, userData)
    .replace(/\$\{workspace\}/g, workspaceRoot);
}

/** 解析 MCP server 注册表：defaults 为基准，环境变量覆盖内置 server，userData JSON 覆盖全部 */
function resolveMcpServers(
  defaultServers: Array<{ id: string; name: string; type: "local" | "sse" | "streamable-http"; enabled: boolean; builtIn: boolean; command?: string; args?: string[]; env?: Record<string, string>; url?: string }>
) {
  let servers = defaultServers.map((s) => ({ ...s }));
  // 环境变量覆盖内置 server（dev 模式：PCAPAI_TSHARK_QUERY_MCP_* 优先）
  const tsharkCmd = process.env.PCAPAI_TSHARK_QUERY_MCP_COMMAND;
  const tsharkArgs = process.env.PCAPAI_TSHARK_QUERY_MCP_ARGS?.split(" ").filter(Boolean);
  if (tsharkCmd || tsharkArgs) {
    const idx = servers.findIndex((s) => s.id === "tshark-query");
    if (idx >= 0) {
      if (tsharkCmd) servers[idx].command = tsharkCmd;
      if (tsharkArgs) servers[idx].args = tsharkArgs;
    }
  }
  const evidenceCmd = process.env.PCAPAI_EVIDENCE_OPENER_MCP_COMMAND;
  const evidenceArgs = process.env.PCAPAI_EVIDENCE_OPENER_MCP_ARGS?.split(" ").filter(Boolean);
  if (evidenceCmd || evidenceArgs) {
    const idx = servers.findIndex((s) => s.id === "evidence-opener");
    if (idx >= 0) {
      if (evidenceCmd) servers[idx].command = evidenceCmd;
      if (evidenceArgs) servers[idx].args = evidenceArgs;
    }
  }
  // userData JSON 覆盖（用户编辑的注册表）
  const userDataDir = process.env.PCAPAI_USERDATA_DIR;
  if (userDataDir) {
    const regPath = path.join(userDataDir, "mcp-registries.json");
    try {
      if (existsSync(regPath)) {
        const reg = JSON.parse(readFileSync(regPath, "utf8"));
        if (Array.isArray(reg.servers)) {
          servers = reg.servers;
        }
      }
    } catch {
      // JSON 解析失败用 defaults
    }
  }
  // 路径变量替换（command/args/url 中的 ${resources} 等）
  return servers.map((s) => ({
    ...s,
    command: s.command ? resolvePathVars(s.command) : undefined,
    args: s.args?.map(resolvePathVars),
    url: s.url ? resolvePathVars(s.url) : undefined
  }));
}

/** 解析额外 skills 目录（环境变量 PCAPAI_SKILLS_EXTRA_DIRS 逗号分隔 + defaults extraDirs） */
function resolveSkillsExtraDirs(defaultExtraDirs: string[]): string[] {
  const dirs: string[] = [];
  // 环境变量
  const envDirs = process.env.PCAPAI_SKILLS_EXTRA_DIRS;
  if (envDirs) {
    for (const d of envDirs.split(",").map((s) => s.trim()).filter(Boolean)) {
      dirs.push(resolvePathVars(d));
    }
  }
  // defaults
  for (const d of defaultExtraDirs) {
    dirs.push(resolvePathVars(d));
  }
  // userData 配置文件
  const userDataDir = process.env.PCAPAI_USERDATA_DIR;
  if (userDataDir) {
    const cfgPath = path.join(userDataDir, "skills-config.json");
    try {
      if (existsSync(cfgPath)) {
        const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
        if (Array.isArray(cfg.directories)) {
          for (const d of cfg.directories) {
            dirs.push(resolvePathVars(d));
          }
        }
      }
    } catch {
      // 解析失败忽略
    }
  }
  return [...new Set(dirs)]; // 去重
}
