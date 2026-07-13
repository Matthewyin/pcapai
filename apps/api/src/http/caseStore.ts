import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import {
  AnalysisRunSchema,
  CaptureNodeSchema,
  CaseGraphSchema,
  CaseSpecSchema,
  type AnalysisRun,
  type CaptureNode,
  type CaseGraph,
  type CaseSpec
} from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

export function safePathPart(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}

export function caseDirectory(caseId: string) {
  return path.join(caseDataDirectory(), safePathPart(caseId));
}

export function caseDataDirectory() {
  return process.env.PCAPAI_CASE_DATA_DIR
    ? path.resolve(process.env.PCAPAI_CASE_DATA_DIR)
    : apiConfig.caseDataDir;
}

export function capturesDirectory(caseId: string) {
  return path.join(caseDirectory(caseId), "captures");
}

export function analysisRunsDirectory(caseId: string) {
  return path.join(caseDirectory(caseId), "analysis-runs");
}

function graphPath(caseId: string) {
  return path.join(caseDirectory(caseId), "case.json");
}

function writeJsonAtomically(target: string, value: unknown): void {
  const directory = path.dirname(target);
  const temporary = path.join(directory, `.${path.basename(target)}-${process.pid}-${randomUUID()}.tmp`);
  const content = JSON.stringify(value, null, 2);
  mkdirSync(directory, { recursive: true });
  try {
    writeFileSync(temporary, content, "utf8");
    renameSync(temporary, target);
  } finally {
    if (existsSync(temporary)) rmSync(temporary, { force: true });
  }
}

export function writeCaseGraph(graph: CaseGraph) {
  writeJsonAtomically(graphPath(graph.spec.caseId), graph);
}

export function readCaseGraph(caseId: string) {
  return CaseGraphSchema.parse(JSON.parse(readFileSync(graphPath(caseId), "utf8")));
}

export function listCaseSummaries() {
  const dataDirectory = caseDataDirectory();
  if (!existsSync(dataDirectory)) return [];
  return readdirSync(dataDirectory)
    .flatMap((caseId) => {
      try {
        const graph = readCaseGraph(caseId);
        const stats = statSync(graphPath(caseId));
        return [{
          caseId: graph.spec.caseId,
          title: graph.spec.title,
          updatedAt: stats.mtimeMs,
          captureCount: graph.captures.length,
          rawPacketCount: graph.captures.reduce((sum, capture) => sum + (capture.packetCount || 0), 0),
          packetCount: graph.packets.length,
          findingCount: graph.findings.length,
          runCount: graph.analysisRuns.length,
          activeRunId: graph.activeRunId || ""
        }];
      } catch {
        return [];
      }
    })
    .sort((left, right) => right.updatedAt - left.updatedAt);
}

export function createEmptyCase(spec: CaseSpec) {
  const parsedSpec = CaseSpecSchema.parse(spec);
  const graph: CaseGraph = {
    spec: parsedSpec,
    captures: [],
    mappingHints: [],
    timeOffsetHints: [],
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [],
    analysisRuns: [],
    toolRuns: [],
    insights: [],
    connectionLinks: [],
    memory: { topology: "", findings: [], userNotes: [] }
  };
  writeCaseGraph(graph);
  return graph;
}

export function writeAnalysisRunSnapshot(graph: CaseGraph, run: AnalysisRun) {
  const parsedRun = AnalysisRunSchema.parse(run);
  const directory = analysisRunsDirectory(graph.spec.caseId);
  writeJsonAtomically(path.join(directory, parsedRun.snapshotFilename || `${safePathPart(parsedRun.runId)}.json`), graph);
}

export function readAnalysisRunSnapshot(caseId: string, runId: string) {
  return CaseGraphSchema.parse(JSON.parse(readFileSync(path.join(analysisRunsDirectory(caseId), `${safePathPart(runId)}.json`), "utf8")));
}

export function deleteCase(caseId: string) {
  const directory = caseDirectory(caseId);
  if (!existsSync(directory)) return false;
  rmSync(directory, { recursive: true, force: true });
  return true;
}

export function deleteCases(caseIds: string[]) {
  return caseIds.map((caseId) => ({ caseId, deleted: deleteCase(caseId) }));
}

export function addCapture(graph: CaseGraph, capture: CaptureNode) {
  const parsedCapture = CaptureNodeSchema.parse(capture);
  const nextGraph = {
    ...graph,
    captures: [...graph.captures.filter((item) => item.nodeId !== parsedCapture.nodeId), parsedCapture],
    path: {
      ...graph.path,
      nodes: [
        ...graph.path.nodes.filter((item) => item.nodeId !== parsedCapture.nodeId),
        { nodeId: parsedCapture.nodeId, label: parsedCapture.name, role: parsedCapture.role, status: "unknown" as const }
      ]
    }
  };
  writeCaseGraph(nextGraph);
  return nextGraph;
}
