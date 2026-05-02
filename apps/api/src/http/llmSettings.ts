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
const profileKeyPattern = /^PCAPAI_LLM_PROFILE_(.+)_(NAME|BASE_URL|MODEL|API_KEY|PROVIDER_DATA)$/;

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
    providerData: `PCAPAI_LLM_PROFILE_${envId}_PROVIDER_DATA`
  };
}

export function parseProviderData(value: string | undefined): Record<string, unknown> {
  if (!value?.trim()) return {};
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("兼容参数 JSON 必须是对象。");
  }
  return parsed as Record<string, unknown>;
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
  providerData: string;
  hasKey: boolean;
  active: boolean;
};

export function getLlmSettings() {
  return {
    baseURL: apiConfig.llm.baseURL,
    model: apiConfig.llm.model,
    providerData: JSON.stringify(apiConfig.llm.providerData),
    hasKey: Boolean(apiConfig.llm.apiKey),
    activeProfileId: parseEnvFile().get("PCAPAI_LLM_ACTIVE_PROFILE") || ""
  };
}

export function saveLlmSettings(input: { baseURL: string; model: string; apiKey?: string; providerData?: string }) {
  const nextValues = new Map(parseEnvFile());
  const profileId = normalizeProfileId(input.model);
  const keys = profileKeys(profileId);
  const providerData = parseProviderData(input.providerData);
  const providerDataText = JSON.stringify(providerData);
  nextValues.set("PCAPAI_LLM_BASE_URL", input.baseURL);
  nextValues.set("PCAPAI_LLM_MODEL", input.model);
  nextValues.set("PCAPAI_LLM_PROVIDER_DATA", providerDataText);
  nextValues.set("PCAPAI_LLM_ACTIVE_PROFILE", profileId);
  nextValues.set(keys.name, input.model);
  nextValues.set(keys.baseURL, input.baseURL);
  nextValues.set(keys.model, input.model);
  nextValues.set(keys.providerData, providerDataText);
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
    providerData
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
      providerData: values.get(keys.providerData) || "",
      hasKey: Boolean(values.get(keys.apiKey)),
      active: activeProfileId === profileId
    };
  });
}

export function saveLlmProfile(input: { profileId?: string; name: string; baseURL: string; model: string; apiKey?: string; providerData?: string }) {
  const profileId = normalizeProfileId(input.profileId || input.name);
  const keys = profileKeys(profileId);
  const current = parseEnvFile();
  const providerData = parseProviderData(input.providerData);
  const providerDataText = JSON.stringify(providerData);
  const nextValues = new Map<string, string>([
    [keys.name, input.name],
    [keys.baseURL, input.baseURL],
    [keys.model, input.model],
    [keys.providerData, providerDataText],
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
  updateLlmConfig({ baseURL: input.baseURL, model: input.model, apiKey: nextApiKey, providerData });
  return { profile: listLlmProfiles().find((profile) => profile.profileId === profileId), settings: getLlmSettings() };
}

export function activateLlmProfile(profileId: string) {
  const keys = profileKeys(profileId);
  const values = parseEnvFile();
  const baseURL = values.get(keys.baseURL);
  const model = values.get(keys.model);
  if (!baseURL || !model) return null;
  const apiKey = values.get(keys.apiKey) || "";
  const providerDataText = values.get(keys.providerData) || "{}";
  const providerData = parseProviderData(providerDataText);
  const nextValues = new Map<string, string>([
    ["PCAPAI_LLM_BASE_URL", baseURL],
    ["PCAPAI_LLM_MODEL", model],
    ["PCAPAI_LLM_PROVIDER_DATA", providerDataText],
    ["PCAPAI_LLM_ACTIVE_PROFILE", profileId]
  ]);
  if (apiKey) nextValues.set("PCAPAI_LLM_API_KEY", apiKey);
  writeEnvValues((key) => currentManagedKeys.includes(key), nextValues);
  updateLlmConfig({ baseURL, model, apiKey, providerData });
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
