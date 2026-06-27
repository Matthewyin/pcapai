import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { apiConfig, updateLlmConfig } from "../config.js";

function resolveWorkspaceRoot() {
  const candidates = [
    process.env.PCAPAI_ROOT ? path.resolve(process.env.PCAPAI_ROOT) : "",
    process.cwd(),
    path.resolve(process.cwd(), "../..")
  ].filter(Boolean);

  return candidates.find((candidate) => existsSync(path.join(candidate, "config/defaults.json"))) || process.cwd();
}

const envPath = path.join(resolveWorkspaceRoot(), ".env");
const currentManagedKeys = ["PCAPAI_LLM_BASE_URL", "PCAPAI_LLM_MODEL", "PCAPAI_LLM_API_KEY", "PCAPAI_LLM_PROVIDER_DATA", "PCAPAI_LLM_ACTIVE_PROFILE"];
const profileKeyPattern = /^PCAPAI_LLM_PROFILE_(.+)_(NAME|BASE_URL|MODEL|API_KEY|THINKING_DEPTH|REASONING_DEPTH|TEMPERATURE|MAX_TOKENS)$/;

function parseEnvFile() {
  if (!existsSync(envPath)) return new Map<string, string>();
  const entries = new Map<string, string>();
  for (const line of readFileSync(envPath, "utf8").split("\n")) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (match) entries.set(match[1], parseEnvValue(match[2]));
  }
  return entries;
}

function parseEnvValue(value: string) {
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === "string" ? parsed : value;
  } catch {
    return value.replace(/^"|"$/g, "");
  }
}

function formatEnvValue(value: string) {
  return JSON.stringify(value);
}

function readEnvLines() {
  return existsSync(envPath) ? readFileSync(envPath, "utf8").split("\n") : [];
}

function profileEnvId(profileId: string) {
  return profileId.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
}

function normalizeProfileId(value: string) {
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return normalized || `profile_${Date.now()}`;
}

function profileKeys(profileId: string) {
  const envId = profileEnvId(profileId);
  return {
    name: `PCAPAI_LLM_PROFILE_${envId}_NAME`,
    baseURL: `PCAPAI_LLM_PROFILE_${envId}_BASE_URL`,
    model: `PCAPAI_LLM_PROFILE_${envId}_MODEL`,
    apiKey: `PCAPAI_LLM_PROFILE_${envId}_API_KEY`,
    thinkingDepth: `PCAPAI_LLM_PROFILE_${envId}_THINKING_DEPTH`,
    reasoningDepth: `PCAPAI_LLM_PROFILE_${envId}_REASONING_DEPTH`,
    temperature: `PCAPAI_LLM_PROFILE_${envId}_TEMPERATURE`,
    maxTokens: `PCAPAI_LLM_PROFILE_${envId}_MAX_TOKENS`
  };
}

// 思考/推理深度选项（与前端下拉框一致）
export const THINKING_DEPTHS = ["快速", "标准", "深入"] as const;
export const REASONING_DEPTHS = ["低", "标准", "高"] as const;

/**
 * 把「思考深度 + 推理深度」映射成供应商能识别的请求参数。
 * - GLM（bigmodel.cn）：thinking.type（开/关思考）+ reasoning_effort（思考强度）
 * - DeepSeek / 其他：只下发 reasoning_effort（DeepSeek 的 low/medium 会被供应商映射成 high，但参数本身有效）
 * 这些参数会覆盖写进 providerData（SDK 顶层 spread 时优先级最高）。
 */
export function depthToProviderData(baseURL: string, thinkingDepth: string, reasoningDepth: string): Record<string, unknown> {
  const isGlm = baseURL.includes("bigmodel.cn");
  const reasoningMap: Record<string, string> = { "低": "low", "标准": "medium", "高": "max" };
  const result: Record<string, unknown> = {};
  if (isGlm) {
    result.thinking = { type: thinkingDepth === "快速" ? "disabled" : "enabled" };
  }
  result.reasoning_effort = reasoningMap[reasoningDepth] || "medium";
  return result;
}

function normalizeDepth(value: string | undefined, allowed: readonly string[], fallback: string): string {
  return value && (allowed as readonly string[]).includes(value) ? value : fallback;
}

// 可选数值参数：env 存字符串，空/非法 → undefined（不传给供应商），有效 → 数字
function normalizeOptionalNumber(value: string | undefined): number | undefined {
  if (!value || !value.trim()) return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}

export function parseProviderData(value: string | undefined): Record<string, unknown> {
  if (!value?.trim()) return {};
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("兼容参数 JSON 必须是对象。");
  }
  return parsed as Record<string, unknown>;
}

/**
 * 按被测配置（baseURL / model）反查对应 profile 的 API Key。
 * 测试时前端出于安全不回传 key（llmForm.apiKey 恒为空），后端不能直接 fallback 到
 * 当前激活 profile 的 key（apiConfig.llm.apiKey）——否则测 DeepSeek 会用到激活的 GLM key。
 * 这里改为：先精确匹配 baseURL+model 的 profile，再退而求其次只匹配 baseURL，最后才用全局 key。
 */
export function resolveApiKeyForConfig(baseURL: string, model: string): string {
  const values = parseEnvFile();
  const profiles: Array<{ apiKey: string; baseURL: string; model: string }> = [];
  const profileIds = new Set<string>();
  for (const key of values.keys()) {
    const match = key.match(profileKeyPattern);
    if (match) profileIds.add(match[1].toLowerCase());
  }
  for (const profileId of profileIds) {
    const keys = profileKeys(profileId);
    const apiKey = values.get(keys.apiKey) || "";
    if (apiKey) profiles.push({ apiKey, baseURL: values.get(keys.baseURL) || "", model: values.get(keys.model) || "" });
  }
  // 1. baseURL + model 双匹配（最精确）
  const exact = profiles.find((p) => p.baseURL === baseURL && p.model === model);
  if (exact) return exact.apiKey;
  // 2. 仅 baseURL 匹配（同供应商不同模型，如 glm-5.2 / glm-4.7 共用 coding/paas/v4）
  const byHost = profiles.find((p) => p.baseURL === baseURL);
  if (byHost) return byHost.apiKey;
  // 3. 兜底：当前激活 profile 的 key（兼容未建档的临时配置）
  return apiConfig.llm.apiKey;
}

function writeEnvValues(removeKey: (key: string) => boolean, values: Map<string, string>) {
  const retained = readEnvLines().filter((line) => {
    const key = line.match(/^([A-Z0-9_]+)=/)?.[1];
    return key ? !removeKey(key) : line.trim().length > 0;
  });
  const managed = [...values.entries()].map(([key, value]) => `${key}=${key.endsWith("_PROVIDER_DATA") ? value : formatEnvValue(value)}`);
  writeFileSync(envPath, [...retained, ...managed, ""].join("\n"));
}

export type LlmProfile = {
  profileId: string;
  name: string;
  baseURL: string;
  model: string;
  thinkingDepth: string;
  reasoningDepth: string;
  temperature: string;
  maxTokens: string;
  hasKey: boolean;
  active: boolean;
};

export function getLlmSettings() {
  const values = parseEnvFile();
  const activeProfileId = values.get("PCAPAI_LLM_ACTIVE_PROFILE") || "";
  // 激活 profile 的思考/推理深度（全局回退到标准）
  let thinkingDepth = "标准";
  let reasoningDepth = "标准";
  let temperature = "";
  let maxTokens = "";
  if (activeProfileId) {
    const keys = profileKeys(activeProfileId);
    thinkingDepth = normalizeDepth(values.get(keys.thinkingDepth), THINKING_DEPTHS, "标准");
    reasoningDepth = normalizeDepth(values.get(keys.reasoningDepth), REASONING_DEPTHS, "标准");
    temperature = values.get(keys.temperature) || "";
    maxTokens = values.get(keys.maxTokens) || "";
  }
  return {
    baseURL: apiConfig.llm.baseURL,
    model: apiConfig.llm.model,
    thinkingDepth,
    reasoningDepth,
    temperature,
    maxTokens,
    hasKey: Boolean(apiConfig.llm.apiKey),
    activeProfileId
  };
}

export function saveLlmSettings(input: { baseURL: string; model: string; apiKey?: string; thinkingDepth?: string; reasoningDepth?: string; temperature?: string; maxTokens?: string }) {
  const thinkingDepth = normalizeDepth(input.thinkingDepth, THINKING_DEPTHS, "标准");
  const reasoningDepth = normalizeDepth(input.reasoningDepth, REASONING_DEPTHS, "标准");
  const temperature = (input.temperature || "").trim();
  const maxTokens = (input.maxTokens || "").trim();
  const providerData = depthToProviderData(input.baseURL, thinkingDepth, reasoningDepth);
  const providerDataText = JSON.stringify(providerData);
  const nextValues = new Map(parseEnvFile());
  const profileId = normalizeProfileId(input.model);
  const keys = profileKeys(profileId);
  nextValues.set("PCAPAI_LLM_BASE_URL", input.baseURL);
  nextValues.set("PCAPAI_LLM_MODEL", input.model);
  nextValues.set("PCAPAI_LLM_PROVIDER_DATA", providerDataText);
  nextValues.set("PCAPAI_LLM_ACTIVE_PROFILE", profileId);
  nextValues.set(keys.name, input.model);
  nextValues.set(keys.baseURL, input.baseURL);
  nextValues.set(keys.model, input.model);
  nextValues.set(keys.thinkingDepth, thinkingDepth);
  nextValues.set(keys.reasoningDepth, reasoningDepth);
  nextValues.set(keys.temperature, temperature);
  nextValues.set(keys.maxTokens, maxTokens);
  if (input.apiKey !== undefined && input.apiKey.length > 0) {
    nextValues.set("PCAPAI_LLM_API_KEY", input.apiKey);
    nextValues.set(keys.apiKey, input.apiKey);
  } else if (nextValues.get(keys.apiKey)) {
    nextValues.set("PCAPAI_LLM_API_KEY", nextValues.get(keys.apiKey) || "");
  }

  const managed = new Map([...currentManagedKeys, ...Object.values(keys)]
    .filter((key) => nextValues.has(key))
    .map((key) => [key, nextValues.get(key) || ""]));
  const removeKeys = new Set([...currentManagedKeys, ...Object.values(keys)]);
  writeEnvValues((key) => removeKeys.has(key), managed);
  updateLlmConfig({
    baseURL: input.baseURL,
    model: input.model,
    apiKey: nextValues.get(keys.apiKey) || "",
    providerData,
    temperature: normalizeOptionalNumber(temperature),
    maxTokens: normalizeOptionalNumber(maxTokens)
  });

  return getLlmSettings();
}

export function listLlmProfiles(): LlmProfile[] {
  const values = parseEnvFile();
  const activeProfileId = values.get("PCAPAI_LLM_ACTIVE_PROFILE") || "";
  const profileIds = new Set<string>();
  for (const key of values.keys()) {
    const match = key.match(profileKeyPattern);
    if (match) profileIds.add(match[1].toLowerCase());
  }

  return [...profileIds].sort().map((profileId) => {
    const keys = profileKeys(profileId);
    return {
      profileId,
      name: values.get(keys.name) || profileId,
      baseURL: values.get(keys.baseURL) || "",
      model: values.get(keys.model) || "",
      thinkingDepth: normalizeDepth(values.get(keys.thinkingDepth), THINKING_DEPTHS, "标准"),
      reasoningDepth: normalizeDepth(values.get(keys.reasoningDepth), REASONING_DEPTHS, "标准"),
      temperature: values.get(keys.temperature) || "",
      maxTokens: values.get(keys.maxTokens) || "",
      hasKey: Boolean(values.get(keys.apiKey)),
      active: activeProfileId === profileId
    };
  });
}

export function saveLlmProfile(input: { profileId?: string; name: string; baseURL: string; model: string; apiKey?: string; thinkingDepth?: string; reasoningDepth?: string; temperature?: string; maxTokens?: string }) {
  const profileId = normalizeProfileId(input.profileId || input.name);
  const keys = profileKeys(profileId);
  const current = parseEnvFile();
  const thinkingDepth = normalizeDepth(input.thinkingDepth, THINKING_DEPTHS, "标准");
  const reasoningDepth = normalizeDepth(input.reasoningDepth, REASONING_DEPTHS, "标准");
  const temperature = (input.temperature || "").trim();
  const maxTokens = (input.maxTokens || "").trim();
  const providerData = depthToProviderData(input.baseURL, thinkingDepth, reasoningDepth);
  const providerDataText = JSON.stringify(providerData);
  const nextValues = new Map<string, string>([
    [keys.name, input.name],
    [keys.baseURL, input.baseURL],
    [keys.model, input.model],
    [keys.thinkingDepth, thinkingDepth],
    [keys.reasoningDepth, reasoningDepth],
    [keys.temperature, temperature],
    [keys.maxTokens, maxTokens],
    ["PCAPAI_LLM_BASE_URL", input.baseURL],
    ["PCAPAI_LLM_MODEL", input.model],
    ["PCAPAI_LLM_PROVIDER_DATA", providerDataText],
    ["PCAPAI_LLM_ACTIVE_PROFILE", profileId]
  ]);
  const nextApiKey = input.apiKey && input.apiKey.length > 0
    ? input.apiKey
    : current.get(keys.apiKey) || "";
  if (nextApiKey) {
    nextValues.set(keys.apiKey, nextApiKey);
    nextValues.set("PCAPAI_LLM_API_KEY", nextApiKey);
  }

  const removeKeys = new Set(Object.values(keys));
  writeEnvValues((key) => removeKeys.has(key), nextValues);
  updateLlmConfig({ baseURL: input.baseURL, model: input.model, apiKey: nextApiKey, providerData, temperature: normalizeOptionalNumber(temperature), maxTokens: normalizeOptionalNumber(maxTokens) });
  return { profile: listLlmProfiles().find((profile) => profile.profileId === profileId), settings: getLlmSettings() };
}

export function activateLlmProfile(profileId: string) {
  const keys = profileKeys(profileId);
  const values = parseEnvFile();
  const baseURL = values.get(keys.baseURL);
  const model = values.get(keys.model);
  if (!baseURL || !model) return null;
  const apiKey = values.get(keys.apiKey) || "";
  const thinkingDepth = normalizeDepth(values.get(keys.thinkingDepth), THINKING_DEPTHS, "标准");
  const reasoningDepth = normalizeDepth(values.get(keys.reasoningDepth), REASONING_DEPTHS, "标准");
  const temperature = values.get(keys.temperature) || "";
  const maxTokens = values.get(keys.maxTokens) || "";
  const providerData = depthToProviderData(baseURL, thinkingDepth, reasoningDepth);
  const providerDataText = JSON.stringify(providerData);
  const nextValues = new Map<string, string>([
    ["PCAPAI_LLM_BASE_URL", baseURL],
    ["PCAPAI_LLM_MODEL", model],
    ["PCAPAI_LLM_PROVIDER_DATA", providerDataText],
    ["PCAPAI_LLM_ACTIVE_PROFILE", profileId]
  ]);
  if (apiKey) nextValues.set("PCAPAI_LLM_API_KEY", apiKey);
  writeEnvValues((key) => currentManagedKeys.includes(key), nextValues);
  updateLlmConfig({ baseURL, model, apiKey, providerData, temperature: normalizeOptionalNumber(temperature), maxTokens: normalizeOptionalNumber(maxTokens) });
  return getLlmSettings();
}

export function deleteLlmProfiles(profileIds: string[]) {
  const normalized = new Set(profileIds.map((profileId) => profileEnvId(profileId)));
  const values = parseEnvFile();
  const activeProfileId = values.get("PCAPAI_LLM_ACTIVE_PROFILE") || "";
  const removeCurrentActive = normalized.has(profileEnvId(activeProfileId));
  const nextValues = new Map<string, string>();
  if (removeCurrentActive) nextValues.set("PCAPAI_LLM_ACTIVE_PROFILE", "");
  writeEnvValues((key) => {
    const match = key.match(profileKeyPattern);
    return Boolean(match && normalized.has(match[1])) || (removeCurrentActive && key === "PCAPAI_LLM_ACTIVE_PROFILE");
  }, nextValues);
  return { profiles: listLlmProfiles(), settings: getLlmSettings() };
}
