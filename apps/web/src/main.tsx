import React from "react";
import ReactDOM from "react-dom/client";
import { BookOpen, CheckCircle, Eye, EyeOff, History, Moon, Pencil, Save, Settings, Sun, Trash2, X } from "lucide-react";
import { webConfig } from "./config";
import "./styles.css";

type CaseGraph = {
  spec: { caseId: string; title: string; client?: string; server?: string; port?: number; protocol: string };
  captures: { nodeId: string; name: string; role: string; capturePosition: string }[];
  mappingHints: MappingHint[];
  timeOffsetHints: TimeOffsetHint[];
  rawPackets: {
    packetId: string;
  }[];
  analysisFilter: { client?: string; server?: string; protocol?: string; port?: number };
  packets: {
    packetId: string;
    frameNumber: number;
    timestamp: number;
    srcIp?: string;
    srcPort?: number;
    dstIp?: string;
    dstPort?: number;
    protocol: string;
    tcpFlags: string[];
    length?: number;
    summary: string;
  }[];
  sessions: {
    segmentId: string;
    nodeId: string;
    protocol: string;
    clientIp?: string;
    clientPort?: number;
    serverIp?: string;
    serverPort?: number;
    startTime: number;
    endTime: number;
    packetIds: string[];
    eventKinds: string[];
    summary: string;
    confidence: string;
  }[];
  sessionLinks: {
    linkId: string;
    fromSegmentId: string;
    toSegmentId: string;
    fromNodeId: string;
    toNodeId: string;
    matchReasons: string[];
    counterEvidence: string[];
    confidence: string;
    score: number;
  }[];
  findings: { findingId: string; title: string; summary: string; confidence: string; evidenceIds: string[]; nextSteps: string[] }[];
  evidence: { evidenceId: string; title: string; detail: string; packetIds: string[] }[];
  path: { nodes: { nodeId: string; label: string; role: string; status: string }[]; edges: { edgeId: string; label: string; status: string }[] };
  analysisRuns: AnalysisRun[];
  activeRunId?: string;
};

type AnalysisRun = {
  runId: string;
  createdAt: string;
  kind: "capture_update" | "parse" | "analysis";
  summary: string;
  captureCount: number;
  rawPacketCount: number;
  packetCount: number;
  findingCount: number;
};

type MappingHint = {
  hintId: string;
  kind: "nat" | "slb" | "proxy" | "gateway" | "tunnel";
  fromNodeId?: string;
  toNodeId?: string;
  originalSrcIp?: string;
  originalSrcPort?: number;
  originalDstIp?: string;
  originalDstPort?: number;
  translatedSrcIp?: string;
  translatedSrcPort?: number;
  translatedDstIp?: string;
  translatedDstPort?: number;
  note: string;
};

type TimeOffsetHint = {
  hintId: string;
  fromNodeId?: string;
  toNodeId?: string;
  offsetSeconds: number;
  note: string;
};

type CaseSummary = {
  caseId: string;
  title: string;
  updatedAt: number;
  captureCount: number;
  rawPacketCount: number;
  packetCount: number;
  findingCount: number;
  runCount: number;
  activeRunId: string;
};

type LlmProfile = {
  profileId: string;
  name: string;
  baseURL: string;
  model: string;
  hasKey: boolean;
  active: boolean;
};

type LlmRuntimeStatus = {
  settings: {
    baseURL: string;
    model: string;
    hasKey: boolean;
    activeProfileId: string;
  };
  useResponses: boolean;
  agent: {
    lastRunAt: string;
    lastStatus: string;
    lastError: string;
    lastCaseId: string;
    lastModel: string;
    lastBaseURL: string;
  };
};

type CaptureDraft = {
  file: File;
  nodeId: string;
  name: string;
  role: string;
  interfaceDirection: "unknown" | "ingress" | "egress" | "bidirectional";
  capturePosition: string;
};

type DetailView = "path" | "findings" | "sessions" | "links" | "packets" | "events";
type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  thoughts?: string[];
  streaming?: boolean;
};

function fileStem(filename: string) {
  return filename.replace(/\.[^.]+$/, "");
}

function formatApiError(data: unknown) {
  if (typeof data === "object" && data !== null && "error" in data) {
    const error = data.error;
    if (typeof error === "string") return error;
    if (typeof error === "object" && error !== null && "fieldErrors" in error) {
      const fieldErrors = error.fieldErrors as Record<string, string[]>;
      return Object.entries(fieldErrors)
        .flatMap(([field, messages]) => messages.map((message) => `${field}: ${message}`))
        .join("；");
    }
  }
  return JSON.stringify(data);
}

function runKindLabel(kind: AnalysisRun["kind"]) {
  if (kind === "capture_update") return "数据更新";
  if (kind === "parse") return "原始解析";
  return "条件分析";
}

function detailTitle(view: DetailView) {
  if (view === "path") return "访问路径";
  if (view === "findings") return "判断结果";
  if (view === "sessions") return "会话片段";
  if (view === "links") return "跨节点关联";
  if (view === "packets") return "数据包";
  return "关键事件";
}

function formatPacketTime(timestamp?: number) {
  if (!Number.isFinite(timestamp)) return "-";
  const milliseconds = timestamp! > 1_000_000_000_000 ? timestamp! : timestamp! * 1000;
  return new Date(milliseconds).toLocaleString();
}

function App() {
  const [page, setPage] = React.useState<"workbench" | "history" | "settings" | "help">("workbench");
  const [theme, setTheme] = React.useState<"dark" | "light">(() => {
    return localStorage.getItem("pcapai-theme") === "dark" ? "dark" : "light";
  });
  const [detailView, setDetailView] = React.useState<DetailView | null>(null);
  const [graph, setGraph] = React.useState<CaseGraph | null>(null);
  const [answer, setAnswer] = React.useState("");
  const [chatMessages, setChatMessages] = React.useState<ChatMessage[]>([]);
  const [report, setReport] = React.useState("");
  const [question, setQuestion] = React.useState(webConfig.defaultQuestion);
  const [status, setStatus] = React.useState("请先新建案例，再上传 pcap。");
  const [caseForm, setCaseForm] = React.useState({ title: "新建离线排障案例" });
  const [analysisFilter, setAnalysisFilter] = React.useState({ client: "", server: "", protocol: "", port: "" });
  const [caseHistory, setCaseHistory] = React.useState<CaseSummary[]>([]);
  const [mappingHints, setMappingHints] = React.useState<MappingHint[]>([]);
  const [timeOffsetHints, setTimeOffsetHints] = React.useState<TimeOffsetHint[]>([]);
  const [captureDrafts, setCaptureDrafts] = React.useState<CaptureDraft[]>([]);
  const [llmForm, setLlmForm] = React.useState({ baseURL: "", model: "", apiKey: "" });
  const [showLlmApiKey, setShowLlmApiKey] = React.useState(false);
  const [llmProfileForm, setLlmProfileForm] = React.useState({ profileId: "", name: "", baseURL: "", model: "", apiKey: "" });
  const [llmProfiles, setLlmProfiles] = React.useState<LlmProfile[]>([]);
  const [chatProfileId, setChatProfileId] = React.useState("");
  const [thinkingDepth, setThinkingDepth] = React.useState("标准");
  const [reasoningDepth, setReasoningDepth] = React.useState("标准");
  const [llmRuntime, setLlmRuntime] = React.useState<LlmRuntimeStatus | null>(null);
  const [selectedCaseIds, setSelectedCaseIds] = React.useState<string[]>([]);
  const [selectedProfileIds, setSelectedProfileIds] = React.useState<string[]>([]);
  const [llmStatus, setLlmStatus] = React.useState("");
  const chatMessagesRef = React.useRef<HTMLDivElement | null>(null);
  const uploadDisabledReason = !graph ? "请先新建案例。" : !captureDrafts.length ? "请选择一个或多个 pcap/pcapng 文件。" : "";

  async function loadCaseHistory() {
    const response = await fetch("/api/cases");
    const data = await response.json();
    if (response.ok) {
      const cases = data.cases || [];
      setCaseHistory(cases);
      setSelectedCaseIds((ids) => ids.filter((id) => cases.some((item: CaseSummary) => item.caseId === id)));
    }
  }

  function toggleCaseSelection(caseId: string) {
    setSelectedCaseIds((ids) => ids.includes(caseId) ? ids.filter((id) => id !== caseId) : [...ids, caseId]);
  }

  async function deleteSelectedCases() {
    if (!selectedCaseIds.length) return;
    const response = await fetch("/api/cases", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ caseIds: selectedCaseIds })
    });
    const data = await response.json();
    if (response.ok) {
      if (graph && selectedCaseIds.includes(graph.spec.caseId)) setGraph(null);
      setCaseHistory(data.cases || []);
      setSelectedCaseIds([]);
    }
    setStatus(response.ok ? "已删除选中的历史案例。" : formatApiError(data));
  }

  async function openCase(caseId: string) {
    const response = await fetch(`/api/cases/${caseId}`);
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      setAnalysisFilter({
        client: data.analysisFilter?.client || "",
        server: data.analysisFilter?.server || "",
        protocol: data.analysisFilter?.protocol || "",
        port: data.analysisFilter?.port ? String(data.analysisFilter.port) : ""
      });
      setPage("workbench");
    }
    setStatus(response.ok ? "历史案例已加载。" : formatApiError(data));
  }

  async function openAnalysisRun(runId: string) {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/analysis-runs/${runId}`);
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      setAnalysisFilter({
        client: data.analysisFilter?.client || "",
        server: data.analysisFilter?.server || "",
        protocol: data.analysisFilter?.protocol || "",
        port: data.analysisFilter?.port ? String(data.analysisFilter.port) : ""
      });
    }
    setStatus(response.ok ? "已切换到该分析版本快照。" : formatApiError(data));
  }

  async function loadLlmSettings() {
    const response = await fetch("/api/settings/llm");
    const data = await response.json();
    setLlmForm({ baseURL: data.baseURL || "", model: data.model || "", apiKey: "" });
    setLlmStatus(data.hasKey ? "已配置 Key。" : "未配置 Key。");
  }

  async function loadLlmProfiles() {
    const response = await fetch("/api/settings/llm/profiles");
    const data = await response.json();
    if (response.ok) {
      const profiles = data.profiles || [];
      setLlmProfiles(profiles);
      setSelectedProfileIds((ids) => ids.filter((id) => profiles.some((profile: LlmProfile) => profile.profileId === id)));
    }
  }

  async function loadLlmRuntime() {
    const response = await fetch("/api/settings/llm/runtime");
    const data = await response.json();
    if (response.ok) setLlmRuntime(data);
  }

  async function saveLlmSettings() {
    if (!llmForm.baseURL.trim() || !llmForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    const response = await fetch("/api/settings/llm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok ? (data.hasKey ? "LLM 配置已保存，并已自动生成模型档案。" : "LLM 配置已保存，并已自动生成模型档案，尚未配置 Key。") : formatApiError(data));
    if (response.ok) setLlmForm({ baseURL: data.baseURL, model: data.model, apiKey: "" });
    if (response.ok && data.profiles) setLlmProfiles(data.profiles);
    if (response.ok) {
      await loadLlmProfiles();
      await loadLlmRuntime();
    }
  }

  async function testLlmSettings() {
    if (!llmForm.baseURL.trim() || !llmForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    setLlmStatus("正在测试模型配置...");
    const response = await fetch("/api/settings/llm/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok && data.ok ? "模型配置测试通过。" : `模型配置测试失败：${formatApiError(data)}`);
  }

  function editLlmProfile(profile: LlmProfile) {
    setLlmForm({ baseURL: profile.baseURL, model: profile.model, apiKey: "" });
    setLlmStatus(`已加载 ${profile.name} 到左侧表单。`);
  }

  function toggleProfileSelection(profileId: string) {
    setSelectedProfileIds((ids) => ids.includes(profileId) ? ids.filter((id) => id !== profileId) : [...ids, profileId]);
  }

  async function saveLlmProfile() {
    if (!llmProfileForm.name.trim() || !llmProfileForm.baseURL.trim() || !llmProfileForm.model.trim()) {
      setLlmStatus("配置名称、Base URL 和模型名称不能为空。");
      return;
    }
    const response = await fetch("/api/settings/llm/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmProfileForm)
    });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "" });
      setLlmProfileForm({ profileId: "", name: "", baseURL: "", model: "", apiKey: "" });
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "模型配置档案已保存并启用。" : formatApiError(data));
  }

  async function testLlmProfile() {
    if (!llmProfileForm.baseURL.trim() || !llmProfileForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    setLlmStatus("正在测试模型配置档案...");
    const response = await fetch("/api/settings/llm/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmProfileForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok && data.ok ? "模型配置档案测试通过。" : `模型配置档案测试失败：${formatApiError(data)}`);
  }

  async function activateProfile(profileId: string) {
    const response = await fetch(`/api/settings/llm/profiles/${profileId}/activate`, { method: "POST" });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "" });
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "模型配置档案已启用。" : formatApiError(data));
  }

  async function deleteSelectedProfiles() {
    if (!selectedProfileIds.length) return;
    const response = await fetch("/api/settings/llm/profiles", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profileIds: selectedProfileIds })
    });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setSelectedProfileIds([]);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "" });
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "已删除选中的模型配置档案。" : formatApiError(data));
  }

  async function createCase() {
    if (!caseForm.title.trim()) {
      setStatus("案例名称不能为空。");
      return;
    }
    setStatus("正在创建案例...");
    const response = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(caseForm)
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      await loadCaseHistory();
    }
    setStatus(response.ok ? "案例已创建。" : formatApiError(data));
  }

  async function uploadAndParse() {
    if (!graph || !captureDrafts.length) return;
    setStatus("正在上传抓包文件...");
    const formData = new FormData();
    formData.append("metadata", JSON.stringify(captureDrafts.map(({ file, ...metadata }) => ({ ...metadata, originalName: file.name }))));
    captureDrafts.forEach(({ file }) => formData.append("pcap", file));

    const uploadResponse = await fetch(`/api/cases/${graph.spec.caseId}/captures`, { method: "POST", body: formData });
    const uploadData = await uploadResponse.json();
    if (!uploadResponse.ok) {
      setStatus(formatApiError(uploadData));
      return;
    }

    setStatus("正在调用 packet-parser MCP 解析...");
    const parseResponse = await fetch(`/api/cases/${graph.spec.caseId}/parse`, { method: "POST" });
    const parseData = await parseResponse.json();
    if (parseResponse.ok) {
      setGraph(parseData);
      setMappingHints(parseData.mappingHints || []);
      setTimeOffsetHints(parseData.timeOffsetHints || []);
      setCaptureDrafts([]);
      await loadCaseHistory();
    }
    setStatus(parseResponse.ok ? `原始解析完成，读取到 ${parseData.rawPackets?.length || 0} 个数据包。` : formatApiError(parseData));
  }

  async function analyzeCurrentFilter() {
    if (!graph) return;
    setStatus("正在按筛选条件分析...");
    const analyzeResponse = await fetch(`/api/cases/${graph.spec.caseId}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: analysisFilter.client.trim() || undefined,
        server: analysisFilter.server.trim() || undefined,
        protocol: analysisFilter.protocol.trim() || undefined,
        port: analysisFilter.port ? Number(analysisFilter.port) : undefined
      })
    });
    const analyzeData = await analyzeResponse.json();
    if (analyzeResponse.ok) {
      setGraph(analyzeData);
      setMappingHints(analyzeData.mappingHints || []);
      setTimeOffsetHints(analyzeData.timeOffsetHints || []);
      await loadCaseHistory();
    }
    setStatus(analyzeResponse.ok ? `分析完成，当前筛选命中 ${analyzeData.packets?.length || 0} 个数据包。` : formatApiError(analyzeData));
  }

  function setSelectedFiles(files: File[]) {
    setCaptureDrafts(files.map((file, index) => ({
      file,
      nodeId: `node-${index + 1}`,
      name: fileStem(file.name) || `抓包节点 ${index + 1}`,
      role: "未知节点",
      interfaceDirection: "unknown",
      capturePosition: ""
    })));
  }

  function updateCaptureDraft(index: number, patch: Partial<Omit<CaptureDraft, "file">>) {
    setCaptureDrafts((drafts) => drafts.map((draft, draftIndex) => (draftIndex === index ? { ...draft, ...patch } : draft)));
  }

  function addMappingHint() {
    setMappingHints((hints) => [...hints, { hintId: `hint-${hints.length + 1}`, kind: "nat", note: "" }]);
  }

  function updateMappingHint(index: number, patch: Partial<MappingHint>) {
    setMappingHints((hints) => hints.map((hint, hintIndex) => (hintIndex === index ? { ...hint, ...patch } : hint)));
  }

  function removeMappingHint(index: number) {
    setMappingHints((hints) => hints.filter((_, hintIndex) => hintIndex !== index));
  }

  function numberOrUndefined(value: string) {
    return value ? Number(value) : undefined;
  }

  async function saveMappingHints() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/mapping-hints`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappingHints })
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
    }
    setStatus(response.ok ? "地址转换线索已保存。" : formatApiError(data));
  }

  function addTimeOffsetHint() {
    setTimeOffsetHints((hints) => [...hints, { hintId: `time-${hints.length + 1}`, offsetSeconds: 0, note: "" }]);
  }

  function updateTimeOffsetHint(index: number, patch: Partial<TimeOffsetHint>) {
    setTimeOffsetHints((hints) => hints.map((hint, hintIndex) => (hintIndex === index ? { ...hint, ...patch } : hint)));
  }

  function removeTimeOffsetHint(index: number) {
    setTimeOffsetHints((hints) => hints.filter((_, hintIndex) => hintIndex !== index));
  }

  async function saveTimeOffsetHints() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/time-offset-hints`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timeOffsetHints })
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setTimeOffsetHints(data.timeOffsetHints || []);
    }
    setStatus(response.ok ? "时间偏移线索已保存。" : formatApiError(data));
  }

  async function ask() {
    const prompt = question.trim();
    if (!graph || !prompt) return;
    const userMessage: ChatMessage = { id: `user-${Date.now()}`, role: "user", content: prompt };
    const assistantId = `assistant-${Date.now()}`;
    setChatMessages((messages) => [...messages, userMessage, { id: assistantId, role: "assistant", content: "", thoughts: [], streaming: true }]);
    setQuestion("");
    setAnswer("");

    const response = await fetch(`/api/cases/${graph.spec.caseId}/agent/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: prompt, profileId: chatProfileId || undefined, thinkingDepth, reasoningDepth })
    });
    if (!response.ok || !response.body) {
      const data = await response.json();
      const error = formatApiError(data);
      setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: error, streaming: false } : message));
      await loadLlmRuntime();
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const applyEvent = (rawEvent: string) => {
      const event = rawEvent.match(/^event: (.+)$/m)?.[1];
      const dataLine = rawEvent.match(/^data: (.+)$/m)?.[1];
      if (!event || !dataLine) return;
      const data = JSON.parse(dataLine);
      if (event === "thought") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, thoughts: [...(message.thoughts || []), data.text] } : message));
      } else if (event === "delta") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: message.content + data.text } : message));
      } else if (event === "done") {
        setAnswer(data.answer || "");
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.answer || message.content, streaming: false } : message));
      } else if (event === "error") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.error, streaming: false } : message));
      }
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      events.forEach(applyEvent);
    }
    if (buffer.trim()) applyEvent(buffer);
    setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, streaming: false } : message));
    await loadLlmRuntime();
  }

  async function exportReport() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/report`);
    const data = await response.json();
    setReport(response.ok ? data.markdown || "" : formatApiError(data));
  }

  React.useEffect(() => {
    localStorage.setItem("pcapai-theme", theme);
  }, [theme]);

  React.useEffect(() => {
    void loadLlmSettings();
    void loadLlmProfiles();
    void loadLlmRuntime();
    void loadCaseHistory();
  }, []);

  React.useEffect(() => {
    if (chatMessagesRef.current) {
      chatMessagesRef.current.scrollTop = chatMessagesRef.current.scrollHeight;
    }
  }, [chatMessages]);

  const headerSubtitle = page === "workbench"
    ? (graph ? graph.spec.title : "离线网络故障证据链工作台")
    : page === "history"
      ? "历史案例管理"
      : page === "settings"
        ? "本地配置"
        : "使用帮助";
  const tcpConnectionCount = graph?.sessions.filter((session) => session.protocol.toLowerCase() === "tcp").length || 0;
  const packetTimes = (graph?.packets || []).map((packet) => packet.timestamp).filter(Number.isFinite);
  const timeRange = packetTimes.length
    ? `${formatPacketTime(Math.min(...packetTimes))} - ${formatPacketTime(Math.max(...packetTimes))}`
    : "-";

  return (
    <main className="app" data-theme={theme}>
      <header>
        <div>
          <h1>pcapAI</h1>
          <p>{headerSubtitle}</p>
        </div>
        <nav className="topNav">
          <button className={page === "workbench" ? "active" : ""} onClick={() => setPage("workbench")}>工作台</button>
          <button className={page === "history" ? "active" : ""} onClick={() => setPage("history")}>
            <History size={16} /> 历史案例
          </button>
          <button className={page === "settings" ? "active" : ""} onClick={() => setPage("settings")}>
            <Settings size={16} /> 配置
          </button>
          <button className={page === "help" ? "active" : ""} onClick={() => setPage("help")}>
            <BookOpen size={16} /> 帮助
          </button>
          <button
            className="themeToggle"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            title={theme === "dark" ? "切换亮色主题" : "切换暗色主题"}
            aria-label={theme === "dark" ? "切换亮色主题" : "切换暗色主题"}
          >
            {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </nav>
      </header>

      {page === "help" ? (
        <section className="helpPage">
          <section className="helpHero">
            <span>离线多节点 pcap 证据链工作流</span>
            <h2>从抓包文件到访问路径，再到可回溯判断。</h2>
            <p>pcapAI 适合排查 client 到 server 访问失败。系统先用确定性管线解析和关联数据包，再让 Agent 基于 case graph 解释证据，不让大模型直接读取原始 pcap。</p>
          </section>

          <section className="helpGrid">
            <article>
              <strong>1. 新建案例</strong>
              <p>在工作台左侧输入案例名称即可创建。案例不需要预先填写源、目的和端口，后续在分析筛选中再收敛目标流量。</p>
            </article>
            <article>
              <strong>2. 上传多节点 pcap</strong>
              <p>一次可以选择多个 pcap、pcapng 或 cap 文件。每个文件都要补齐节点名、节点角色、入/出方向和抓包位置。</p>
            </article>
            <article>
              <strong>3. 解析原始包</strong>
              <p>上传时会先裁剪 payload，再调用 packet-parser MCP 生成 packet summary，减少无意义载荷带来的处理成本。</p>
            </article>
            <article>
              <strong>4. 按条件分析</strong>
              <p>填写客户端、服务端、端口和协议筛选目标访问。协议是手工填写字段，留空表示不限制。</p>
            </article>
            <article>
              <strong>5. 补充转换线索</strong>
              <p>NAT、SLB、代理、网关、隧道和时间偏移会影响跨节点关联。缺少线索时系统会降低置信度，不输出确定结论。</p>
            </article>
            <article>
              <strong>6. 查看证据链</strong>
              <p>中间区域依次看访问路径、会话片段、跨节点关联、数据包、判断结果和关键事件。每个 finding 都应能回到 evidence 和 packet。</p>
            </article>
            <article>
              <strong>7. 配置大模型</strong>
              <p>在配置页填写 OpenAI 兼容 Base URL、API Key 和模型名。可以保存多个配置档案并测试连通性。</p>
            </article>
            <article>
              <strong>8. 询问 Agent</strong>
              <p>Leader Agent 通过 case-graph MCP 只读当前 case graph。它负责解释、追问缺失上下文和生成报告，不替代确定性解析管线。</p>
            </article>
          </section>

          <section className="helpPanel">
            <h2>推荐排障顺序</h2>
            <ol>
              <li>先确认每个抓包节点的角色和位置是否正确。</li>
              <li>再确认筛选条件是否命中目标访问流量。</li>
              <li>如果路径断裂，优先补 NAT/SLB/代理线索和时间偏移。</li>
              <li>最后再让 Agent 解释 finding，避免让模型替代证据判断。</li>
            </ol>
          </section>
        </section>
      ) : page === "history" ? (
        <section className="historyPage">
          <section className="historyToolbar">
            <div>
              <h2>历史案例</h2>
              <p>独立管理已创建的排障案例。加载案例后会自动回到工作台继续分析。</p>
            </div>
            <div className="bulkActions">
              <button onClick={() => setSelectedCaseIds(caseHistory.map((item) => item.caseId))} disabled={!caseHistory.length}>全选</button>
              <button onClick={() => setSelectedCaseIds([])} disabled={!selectedCaseIds.length}>清空</button>
              <button className="danger" onClick={deleteSelectedCases} disabled={!selectedCaseIds.length}>
                <Trash2 size={16} /> 删除
              </button>
            </div>
          </section>

          <section className="historyGrid">
            {caseHistory.map((item) => (
              <article className="historyCard" key={item.caseId}>
                <input type="checkbox" checked={selectedCaseIds.includes(item.caseId)} onChange={() => toggleCaseSelection(item.caseId)} aria-label={`选择 ${item.title}`} />
                <button onClick={() => openCase(item.caseId)}>
                  <strong>{item.title}</strong>
                  <span>{item.captureCount} 个节点 / {item.rawPacketCount} 原始包 / {item.packetCount} 筛选包 / {item.findingCount} 个判断</span>
                  <small>{item.runCount} 个分析版本 / {new Date(item.updatedAt).toLocaleString()}</small>
                </button>
              </article>
            ))}
            {!caseHistory.length && <div className="empty">暂无历史案例。</div>}
          </section>
        </section>
      ) : page === "settings" ? (
        <section className="settingsPage">
          <section className="settingsPanel">
            <h2>添加 LLM</h2>
            {llmRuntime && (
              <dl className="runtimeSummary">
                <dt>当前模型</dt>
                <dd>{llmRuntime.settings.model || "-"}</dd>
                <dt>配置档案</dt>
                <dd>{llmRuntime.settings.activeProfileId || "手工配置"}</dd>
                <dt>Key 状态</dt>
                <dd>{llmRuntime.settings.hasKey ? "已配置" : "未配置"}</dd>
                <dt>调用模式</dt>
                <dd>{llmRuntime.useResponses ? "Responses API" : "Chat Completions"}</dd>
              </dl>
            )}
            <div className="savedConfigCard">
              <div>
                <strong>当前已保存配置</strong>
                <span>{llmForm.baseURL || "-"} / {llmForm.model || "-"} / {llmRuntime?.settings.hasKey ? "已保存 Key" : "未保存 Key"}</span>
              </div>
              <button onClick={() => { void loadLlmSettings(); void loadLlmProfiles(); void loadLlmRuntime(); }}>
                查询配置
              </button>
            </div>
            <div className="form">
              <label>
                <span>Base URL</span>
                <input value={llmForm.baseURL} onChange={(event) => setLlmForm({ ...llmForm, baseURL: event.target.value })} placeholder="OpenAI 兼容 Base URL" />
              </label>
              <label>
                <span>模型名称</span>
                <input value={llmForm.model} onChange={(event) => setLlmForm({ ...llmForm, model: event.target.value })} placeholder="模型名称" />
              </label>
              <label>
                <span>API Key</span>
                <div className="secretInput">
                  <input type={showLlmApiKey ? "text" : "password"} value={llmForm.apiKey} onChange={(event) => setLlmForm({ ...llmForm, apiKey: event.target.value })} placeholder="留空则保留已有 Key" />
                  <button type="button" onClick={() => setShowLlmApiKey((visible) => !visible)} title={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"} aria-label={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"}>
                    {showLlmApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </label>
              <button className="primary" onClick={saveLlmSettings} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
                <Save size={16} /> 保存配置
              </button>
              <button onClick={testLlmSettings} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
                测试配置
              </button>
              <span className="status">{llmStatus}</span>
            </div>
          </section>

          <section className="settingsPanel llmListPanel">
            <h2>LLM 列表</h2>
            <div className="bulkActions">
              <button onClick={() => setSelectedProfileIds(llmProfiles.map((profile) => profile.profileId))} disabled={!llmProfiles.length}>全选</button>
              <button onClick={() => setSelectedProfileIds([])} disabled={!selectedProfileIds.length}>清空</button>
              <button className="danger" onClick={deleteSelectedProfiles} disabled={!selectedProfileIds.length}>
                <Trash2 size={16} /> 删除
              </button>
            </div>

            <div className="profileList">
              {llmProfiles.map((profile) => (
                <article className="profileItem" key={profile.profileId}>
                  <input type="checkbox" checked={selectedProfileIds.includes(profile.profileId)} onChange={() => toggleProfileSelection(profile.profileId)} aria-label={`选择 ${profile.name}`} />
                  <div>
                    <strong>{profile.name}</strong>
                    <span>{profile.baseURL} / {profile.model} / {profile.hasKey ? "已保存 Key" : "未保存 Key"}{profile.active ? " / 当前启用" : ""}</span>
                  </div>
                  <button onClick={() => editLlmProfile(profile)} title="编辑配置档案"><Pencil size={16} /></button>
                  <button onClick={() => activateProfile(profile.profileId)} disabled={profile.active} title="启用配置档案"><CheckCircle size={16} /></button>
                </article>
              ))}
              {!llmProfiles.length && <div className="empty">暂无模型配置档案。</div>}
            </div>
          </section>
        </section>
      ) : (
      <section className="workbenchShell">
        <aside className="caseRail panel">
          <h2>案例</h2>
          <div className="form">
            <input value={caseForm.title} onChange={(event) => setCaseForm({ ...caseForm, title: event.target.value })} placeholder="案例名称" />
            <button className="primary" onClick={createCase} disabled={!caseForm.title.trim()}>新建案例</button>
          </div>

          {graph && (
            <dl>
              <dt>案例 ID</dt>
              <dd>{graph.spec.caseId}</dd>
              <dt>筛选</dt>
              <dd>{`${graph.analysisFilter?.client || "*"} -> ${graph.analysisFilter?.server || "*"}:${graph.analysisFilter?.port ?? "*"}`}</dd>
              <dt>包数</dt>
              <dd>{graph.rawPackets?.length || 0} 原始 / {graph.packets.length} 当前</dd>
              <dt>版本</dt>
              <dd>{graph.analysisRuns?.length || 0} 个 run / {graph.activeRunId || "-"}</dd>
            </dl>
          )}

          {graph?.analysisRuns?.length ? (
            <>
              <h2>分析版本</h2>
              <div className="runList">
                {graph.analysisRuns.map((run) => (
                  <button className={`runItem ${run.runId === graph.activeRunId ? "active" : ""}`} key={run.runId} onClick={() => openAnalysisRun(run.runId)}>
                    <strong>{runKindLabel(run.kind)} · {new Date(run.createdAt).toLocaleString()}</strong>
                    <span>{run.summary}</span>
                    <small>{run.rawPacketCount} 原始包 / {run.packetCount} 筛选包 / {run.findingCount} 判断</small>
                  </button>
                ))}
              </div>
            </>
          ) : null}

          <h2>抓包节点</h2>
          <div className="form">
            <input type="file" accept=".pcap,.pcapng,.cap" multiple onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))} />
            {captureDrafts.length ? (
              <div className="captureTable">
                <div className="captureHeader">
                  <span>文件名</span>
                  <span>节点名</span>
                  <span>节点角色</span>
                  <span>入/出方向</span>
                  <span>抓包位置</span>
                </div>
                {captureDrafts.map((draft, index) => (
                  <div className="captureRow" key={`${draft.file.name}-${index}`}>
                    <span title={draft.file.name}>{draft.file.name}</span>
                    <input value={draft.name} onChange={(event) => updateCaptureDraft(index, { name: event.target.value })} placeholder="节点名" />
                    <input value={draft.role} onChange={(event) => updateCaptureDraft(index, { role: event.target.value })} placeholder="节点角色" />
                    <select value={draft.interfaceDirection} onChange={(event) => updateCaptureDraft(index, { interfaceDirection: event.target.value as CaptureDraft["interfaceDirection"] })}>
                      <option value="unknown">未知方向</option>
                      <option value="ingress">入方向</option>
                      <option value="egress">出方向</option>
                      <option value="bidirectional">双向</option>
                    </select>
                    <input value={draft.capturePosition} onChange={(event) => updateCaptureDraft(index, { capturePosition: event.target.value })} placeholder="抓包位置" />
                  </div>
                ))}
              </div>
            ) : null}
            <span className="status">{captureDrafts.length ? `已选择 ${captureDrafts.length} 个文件。` : uploadDisabledReason}</span>
            <button className="primary" onClick={uploadAndParse} disabled={Boolean(uploadDisabledReason)} title={uploadDisabledReason || "上传 pcap 并解析全量 packet summary"}>上传并解析原始包</button>
            <span className="status">{status}</span>
          </div>

          <h2>分析筛选</h2>
          <div className="form">
            <input value={analysisFilter.client} onChange={(event) => setAnalysisFilter({ ...analysisFilter, client: event.target.value })} placeholder="客户端地址，可留空" />
            <input value={analysisFilter.server} onChange={(event) => setAnalysisFilter({ ...analysisFilter, server: event.target.value })} placeholder="服务端地址，可留空" />
            <input value={analysisFilter.port} onChange={(event) => setAnalysisFilter({ ...analysisFilter, port: event.target.value })} placeholder="端口，可留空" />
            <input value={analysisFilter.protocol} onChange={(event) => setAnalysisFilter({ ...analysisFilter, protocol: event.target.value })} placeholder="协议，可留空" />
            <button className="primary" onClick={analyzeCurrentFilter} disabled={!graph || !graph.rawPackets?.length} title={!graph ? "请先新建或加载案例。" : !graph.rawPackets?.length ? "请先上传并解析原始包。" : "按当前筛选条件分析"}>按条件分析</button>
          </div>

          <h2>地址转换线索</h2>
          <div className="mappingActions">
            <button onClick={addMappingHint} disabled={!graph}>新增线索</button>
            <button className="primary" onClick={saveMappingHints} disabled={!graph}>保存线索</button>
          </div>
          {mappingHints.length ? (
            <div className="mappingTable">
              <div className="mappingHeader">
                <span>类型</span><span>起点</span><span>终点</span><span>原源</span><span>原目的</span><span>转换源</span><span>转换目的</span><span>备注</span><span>操作</span>
              </div>
              {mappingHints.map((hint, index) => (
                <div className="mappingRow" key={`${hint.hintId}-${index}`}>
                  <select value={hint.kind} onChange={(event) => updateMappingHint(index, { kind: event.target.value as MappingHint["kind"] })}>
                    <option value="nat">NAT</option>
                    <option value="slb">SLB</option>
                    <option value="proxy">代理</option>
                    <option value="gateway">网关</option>
                    <option value="tunnel">隧道</option>
                  </select>
                  <select value={hint.fromNodeId || ""} onChange={(event) => updateMappingHint(index, { fromNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <select value={hint.toNodeId || ""} onChange={(event) => updateMappingHint(index, { toNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <input value={`${hint.originalSrcIp || ""}${hint.originalSrcPort ? `:${hint.originalSrcPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { originalSrcIp: ip || undefined, originalSrcPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.originalDstIp || ""}${hint.originalDstPort ? `:${hint.originalDstPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { originalDstIp: ip || undefined, originalDstPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.translatedSrcIp || ""}${hint.translatedSrcPort ? `:${hint.translatedSrcPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { translatedSrcIp: ip || undefined, translatedSrcPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.translatedDstIp || ""}${hint.translatedDstPort ? `:${hint.translatedDstPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { translatedDstIp: ip || undefined, translatedDstPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={hint.note} onChange={(event) => updateMappingHint(index, { note: event.target.value })} placeholder="备注" />
                  <button onClick={() => removeMappingHint(index)}>删除</button>
                </div>
              ))}
            </div>
          ) : <div className="empty">暂无地址转换线索。</div>}

          <h2>时间偏移线索</h2>
          <div className="mappingActions">
            <button onClick={addTimeOffsetHint} disabled={!graph}>新增偏移</button>
            <button className="primary" onClick={saveTimeOffsetHints} disabled={!graph}>保存偏移</button>
          </div>
          {timeOffsetHints.length ? (
            <div className="timeOffsetTable">
              <div className="timeOffsetHeader">
                <span>起点</span><span>终点</span><span>终点偏移秒</span><span>备注</span><span>操作</span>
              </div>
              {timeOffsetHints.map((hint, index) => (
                <div className="timeOffsetRow" key={`${hint.hintId}-${index}`}>
                  <select value={hint.fromNodeId || ""} onChange={(event) => updateTimeOffsetHint(index, { fromNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <select value={hint.toNodeId || ""} onChange={(event) => updateTimeOffsetHint(index, { toNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <input type="number" value={hint.offsetSeconds} onChange={(event) => updateTimeOffsetHint(index, { offsetSeconds: Number(event.target.value) })} placeholder="可为负数" />
                  <input value={hint.note} onChange={(event) => updateTimeOffsetHint(index, { note: event.target.value })} placeholder="备注" />
                  <button onClick={() => removeTimeOffsetHint(index)}>删除</button>
                </div>
              ))}
            </div>
          ) : <div className="empty">暂无时间偏移线索。</div>}

          {(graph?.captures || []).map((node) => (
            <article className="node" key={node.nodeId}>
              <strong>{node.name}</strong>
              <span>{node.capturePosition || node.role}</span>
            </article>
          ))}
        </aside>

        <section className="mainDesk">
          <section className="chatPanel panel">
            <div className="chatTopbar">
              <div>
                <h2>Leader Agent</h2>
                <span>{llmRuntime?.agent.lastStatus || "not_run"}{llmRuntime?.agent.lastRunAt ? ` / ${new Date(llmRuntime.agent.lastRunAt).toLocaleString()}` : ""}</span>
              </div>
            </div>

            <div className="chatMessages" ref={chatMessagesRef}>
              {chatMessages.length ? chatMessages.map((message) => (
                <article className={`chatBubble ${message.role === "user" ? "userBubble" : "assistantBubble"}`} key={message.id}>
                  <strong>{message.role === "user" ? "你" : "Agent"}{message.streaming ? " 正在输出..." : ""}</strong>
                  {message.thoughts?.length ? (
                    <details className="thoughtBox" open>
                      <summary>分析过程</summary>
                      <ol>{message.thoughts.map((thought, index) => <li key={`${message.id}-thought-${index}`}>{thought}</li>)}</ol>
                    </details>
                  ) : null}
                  <p>{message.content || (message.streaming ? "等待模型返回..." : "")}</p>
                </article>
              )) : (
                <article className="chatBubble assistantBubble">
                  <strong>Agent</strong>
                  <p>Agent 只读取当前 case graph，不直接解析 pcap。选择模型和深度后，可以直接询问当前访问链路的问题。</p>
                </article>
              )}
              {llmRuntime?.agent.lastError ? (
                <article className="chatBubble errorBubble">
                  <strong>最近错误</strong>
                  <p>{llmRuntime.agent.lastError}</p>
                </article>
              ) : null}
            </div>

            <div className="chatComposer">
              <textarea
                rows={2}
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void ask();
                  }
                }}
                placeholder="输入你要让 Agent 分析的问题，Enter 发送，Shift+Enter 换行"
              />
              <button className="primary" onClick={ask} disabled={!graph || !question.trim()}>发送</button>
              <div className="chatControls">
                <label>
                  <span>LLM</span>
                  <select value={chatProfileId} onChange={(event) => setChatProfileId(event.target.value)}>
                    <option value="">当前配置：{llmRuntime?.settings.model || llmForm.model || "-"}</option>
                    {llmProfiles.map((profile) => (
                      <option value={profile.profileId} key={profile.profileId}>{profile.name} / {profile.model}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>思考深度</span>
                  <select value={thinkingDepth} onChange={(event) => setThinkingDepth(event.target.value)}>
                    <option value="快速">快速</option>
                    <option value="标准">标准</option>
                    <option value="深入">深入</option>
                  </select>
                </label>
                <label>
                  <span>推理深度</span>
                  <select value={reasoningDepth} onChange={(event) => setReasoningDepth(event.target.value)}>
                    <option value="低">低</option>
                    <option value="标准">标准</option>
                    <option value="高">高</option>
                  </select>
                </label>
              </div>
            </div>
          </section>
        </section>

        <aside className="insightDock panel">
          <section className="caseStatusBar">
            <article>
              <span>抓包节点</span>
              <strong>{graph?.captures.length || 0}</strong>
            </article>
            <article>
              <span>原始包</span>
              <strong>{graph?.rawPackets.length || 0}</strong>
            </article>
            <article>
              <span>筛选包</span>
              <strong>{graph?.packets.length || 0}</strong>
            </article>
            <article>
              <span>TCP 连接</span>
              <strong>{tcpConnectionCount}</strong>
            </article>
            <article>
              <span>跨节点关联</span>
              <strong>{graph?.sessionLinks.length || 0}</strong>
            </article>
            <article>
              <span>判断</span>
              <strong>{graph?.findings.length || 0}</strong>
            </article>
            <article className="metricWide">
              <span>当前筛选时间区间</span>
              <b>{timeRange}</b>
            </article>
          </section>

          <section className="evidenceDeck">
            <h2>明细数据</h2>
            <div className="detailLaunchGrid">
              <button onClick={() => setDetailView("path")}>
                <strong>访问路径</strong>
                <span>{graph?.path.nodes.length || 0} 个节点</span>
              </button>
              <button onClick={() => setDetailView("findings")}>
                <strong>判断结果</strong>
                <span>{graph?.findings.length || 0} 条 finding</span>
              </button>
              <button onClick={() => setDetailView("sessions")}>
                <strong>会话片段</strong>
                <span>{graph?.sessions.length || 0} 个片段</span>
              </button>
              <button onClick={() => setDetailView("links")}>
                <strong>跨节点关联</strong>
                <span>{graph?.sessionLinks.length || 0} 条关联</span>
              </button>
              <button onClick={() => setDetailView("packets")}>
                <strong>数据包</strong>
                <span>{graph?.packets.length || 0} 个包</span>
              </button>
              <button onClick={() => setDetailView("events")}>
                <strong>关键事件</strong>
                <span>{graph?.evidence.length || 0} 条证据</span>
              </button>
            </div>
          </section>

          <section className="reportPanel">
            <h2>报告</h2>
            <button className="primary" onClick={exportReport} disabled={!graph}>生成报告</button>
            <pre>{report || "报告基于当前 case graph 生成，不调用大模型。"}</pre>
          </section>
        </aside>
      </section>
      )}
      {detailView && (
        <section className="detailOverlay" role="dialog" aria-modal="true">
          <div className="detailPage">
            <header className="detailHeader">
              <div>
                <h2>{detailTitle(detailView)}</h2>
                <p>{graph ? graph.spec.title : "尚未加载案例"}</p>
              </div>
              <button className="themeToggle" onClick={() => setDetailView(null)} aria-label="关闭详情">
                <X size={18} />
              </button>
            </header>

            <div className="detailBody">
              {detailView === "path" && (
                <>
                  {graph?.path.nodes.length ? (
                    <div className="path detailPath">
                      {graph.path.nodes.map((node, index) => (
                        <React.Fragment key={node.nodeId}>
                          <article className={`pathNode ${node.status}`}>
                            <strong>{node.label}</strong>
                            <span>{node.role}</span>
                          </article>
                          {index < graph.path.edges.length && <span className={`edge ${graph.path.edges[index].status}`}>{graph.path.edges[index].label}</span>}
                        </React.Fragment>
                      ))}
                    </div>
                  ) : <div className="empty">尚未生成访问路径。</div>}
                </>
              )}

              {detailView === "sessions" && (
                <>
                  {graph?.sessions?.length ? (
                    <>
                      <div className="sessionHeader">
                        <span>节点</span><span>协议</span><span>访问方向</span><span>事件</span><span>包数</span><span>置信度</span>
                      </div>
                      <div className="sessionTable">
                        {graph.sessions.map((session) => (
                          <article className="session" key={session.segmentId} title={session.summary}>
                            <strong>{session.nodeId}</strong>
                            <span>{session.protocol.toUpperCase()}</span>
                            <span>{`${session.clientIp || "*"}:${session.clientPort ?? "*"} -> ${session.serverIp || "*"}:${session.serverPort ?? "*"}`}</span>
                            <span>{session.eventKinds.join(", ") || "-"}</span>
                            <span>{session.packetIds.length}</span>
                            <span>{session.confidence}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未生成会话片段。</div>}
                </>
              )}

              {detailView === "links" && (
                <>
                  {graph?.sessionLinks?.length ? (
                    <>
                      <div className="linkHeader">
                        <span>节点</span><span>会话</span><span>依据</span><span>反证</span><span>分数</span><span>置信度</span>
                      </div>
                      <div className="linkTable">
                        {graph.sessionLinks.map((link) => (
                          <article className="linkRow" key={link.linkId} title={[...link.matchReasons, ...link.counterEvidence].join("；")}>
                            <strong>{`${link.fromNodeId} -> ${link.toNodeId}`}</strong>
                            <span>{`${link.fromSegmentId} -> ${link.toSegmentId}`}</span>
                            <span>{link.matchReasons.join("，") || "-"}</span>
                            <span>{link.counterEvidence.join("，") || "-"}</span>
                            <span>{link.score}</span>
                            <span>{link.confidence}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未生成跨节点关联。</div>}
                </>
              )}

              {detailView === "packets" && (
                <>
                  {graph?.packets.length ? (
                    <>
                      <div className="packetHeader">
                        <span>帧</span><span>协议</span><span>源</span><span>目的</span><span>标记</span><span>长度</span>
                      </div>
                      <div className="packetTable">
                        {graph.packets.map((packet) => (
                          <article className="packet" key={packet.packetId} title={packet.summary}>
                            <strong>#{packet.frameNumber}</strong>
                            <span>{packet.protocol.toUpperCase()}</span>
                            <span>{packet.srcIp || "*"}:{packet.srcPort ?? "*"}</span>
                            <span>{packet.dstIp || "*"}:{packet.dstPort ?? "*"}</span>
                            <span>{packet.tcpFlags.join(",") || "-"}</span>
                            <span>{packet.length ?? "-"}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未解析数据包。</div>}
                </>
              )}

              {detailView === "findings" && (
                <>
                  {(graph?.findings || []).map((finding) => (
                    <article className="finding" key={finding.findingId}>
                      <strong>{finding.title}</strong>
                      <p>{finding.summary}</p>
                      <span>置信度：{finding.confidence}</span>
                      <span>证据：{finding.evidenceIds.join("，") || "-"}</span>
                      {finding.nextSteps.length ? <ul>{finding.nextSteps.map((step) => <li key={step}>{step}</li>)}</ul> : null}
                    </article>
                  ))}
                  {!graph?.findings.length && <div className="empty">尚未生成 finding。</div>}
                </>
              )}

              {detailView === "events" && (
                <>
                  {(graph?.evidence || []).map((event) => (
                    <article className="event" key={event.evidenceId}>
                      <strong>{event.title}</strong>
                      <p>{event.detail}</p>
                      <span>{event.evidenceId}</span>
                    </article>
                  ))}
                  {!graph?.evidence.length && <div className="empty">尚未生成证据事件。</div>}
                </>
              )}
            </div>
          </div>
        </section>
      )}
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
