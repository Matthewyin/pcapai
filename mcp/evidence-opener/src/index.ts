import { execFile, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "evidence-opener-mcp", version: "0.1.0" });

const workspaceRoot = (() => {
  const candidates = [
    process.env.PCAPAI_ROOT ? path.resolve(process.env.PCAPAI_ROOT) : "",
    process.cwd(),
    path.resolve(process.cwd(), "../..")
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(path.join(candidate, "config/defaults.json"))) || process.cwd();
})();

const defaults = JSON.parse(readFileSync(path.join(workspaceRoot, "config/defaults.json"), "utf8")) as {
  mcp: { evidenceOpener: { wiresharkCommand: string } };
};

const wiresharkCommand = process.env.PCAPAI_WIRESHARK_COMMAND || defaults.mcp.evidenceOpener.wiresharkCommand || "wireshark";

function wiresharkAppBundle(command: string) {
  if (command.endsWith(".app")) return command;
  const marker = ".app/";
  const index = command.indexOf(marker);
  return index >= 0 ? command.slice(0, index + ".app".length) : "";
}

function wiresharkExecutable(command: string) {
  if (command.endsWith(".app")) return path.join(command, "Contents/MacOS/Wireshark");
  return command;
}

async function openWireshark(pcapPath: string, displayFilter: string, frameNumber?: number) {
  if (!existsSync(pcapPath)) throw new Error(`pcap file not found: ${pcapPath}`);
  const wiresharkArgs = ["-r", pcapPath, "-Y", displayFilter.trim()];
  if (frameNumber) wiresharkArgs.push("-g", String(frameNumber));
  if (process.platform === "darwin") {
    const appBundle = wiresharkAppBundle(wiresharkCommand);
    if (appBundle && existsSync(appBundle)) {
      const args = ["-n", "-a", appBundle, "--args", ...wiresharkArgs];
      await execFileAsync("open", args);
      return { launcher: "open", args };
    }
  }
  const executable = wiresharkExecutable(wiresharkCommand);
  if (existsSync(executable)) {
    const child = spawn(executable, wiresharkArgs, { detached: true, stdio: "ignore" });
    child.unref();
    return { launcher: executable, args: wiresharkArgs };
  }
  if (process.platform === "darwin") {
    const args = ["-na", wiresharkCommand, "--args", ...wiresharkArgs];
    await execFileAsync("open", args);
    return { launcher: "open", args };
  }
  throw new Error(`Wireshark executable not found: ${wiresharkCommand}`);
}

server.registerTool(
  "open_in_wireshark",
  {
    title: "Open in Wireshark",
    description: "Open a local pcap in Wireshark with a display filter.",
    inputSchema: {
      pcapPath: z.string(),
      displayFilter: z.string(),
      frameNumber: z.number().int().optional()
    }
  },
  async ({ pcapPath, displayFilter, frameNumber }) => {
    const launch = await openWireshark(pcapPath, displayFilter, frameNumber);
    return { content: [{ type: "text", text: JSON.stringify({ opened: true, pcapPath, displayFilter, frameNumber, launch }) }] };
  }
);

await server.connect(new StdioServerTransport());
