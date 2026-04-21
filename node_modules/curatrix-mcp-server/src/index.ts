#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { access } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { OsvVulnerabilityProvider } from "curatrix-adapters";
import { applyFixes, scanProject, type Issue, type ScanOptions, type ScanResult } from "curatrix-core";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  name: string;
  version: string;
};

const vulnerabilityProvider = new OsvVulnerabilityProvider();

const server = new McpServer({
  name: "curatrix-mcp",
  version: pkg.version,
});

const scanInputSchema = {
  path: z.string().optional(),
  format: z.enum(["json", "text"]).default("json"),
};

const fixInputSchema = {
  path: z.string().optional(),
  issueIds: z.array(z.string()).optional(),
  autoConfirm: z.boolean().default(true),
};

// Tool: Scan project for vulnerabilities
server.tool(
  "curatrix_scan",
  "Scan the current project for security vulnerabilities using Curatrix.",
  scanInputSchema,
  async (input) => runCuratrixScanTool(input),
);

// Tool: Apply Curatrix fixes
server.tool(
  "curatrix_fix",
  "Apply Curatrix fixes for selected issues in the current project.",
  fixInputSchema,
  async (input) => runCuratrixFixTool(input),
);

export async function runCuratrixScanTool({
  path: targetPath,
  format = "json",
}: {
  path?: string;
  format?: "json" | "text";
}) {
  const rootDir = path.resolve(targetPath ?? process.cwd());
  const validationError = await validateRootDir(rootDir);
  if (validationError) {
    return validationError;
  }

  try {
    const options: ScanOptions = {
      rootDir,
      vulnerabilityProvider,
    };
    const result = await scanProject(options);
    const payload = createScanPayload(result);

    return successResponse(serializeScanPayload(payload, format));
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : String(error));
  }
}

export async function runCuratrixFixTool({
  path: targetPath,
  issueIds,
  autoConfirm = true,
}: {
  path?: string;
  issueIds?: string[];
  autoConfirm?: boolean;
}) {
  const rootDir = path.resolve(targetPath ?? process.cwd());
  const validationError = await validateRootDir(rootDir);
  if (validationError) {
    return validationError;
  }

  try {
    const result = await scanProject({
      rootDir,
      vulnerabilityProvider,
    });

    const issues = selectIssues(result.issues, issueIds);
    const applyResult = await applyFixes({
      rootDir,
      issues,
      autoConfirm,
      vulnerabilityProvider,
    });

    return successResponse({
      rootDir,
      fixedCount: applyResult.applied.length,
      selectedIssues: issues.map((issue) => ({
        id: issue.id,
        ruleId: issue.ruleId,
        title: issue.title,
        source: issue.source,
        correctionContext: buildCorrectionContext(issue),
      })),
      changes: (applyResult.changes ?? []).map((change) => ({
        file: change.file,
        changeType: change.changeType,
        oldValue: change.oldValue,
        newValue: change.newValue,
        diff: change.diff,
        reasoning: toHumanReasoning(change.reasoning),
      })),
      skipped: applyResult.skipped,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : String(error));
  }
}

if (isMainModule(import.meta.url)) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function createScanPayload(result: ScanResult) {
  return {
    project: result.project,
    summary: result.summary,
    policyOutcome: result.policyOutcome,
    featureFlags: result.featureFlags,
    config: result.config,
    issues: result.issues.map((issue) => ({
      id: issue.id,
      ruleId: issue.ruleId,
      severity: issue.severity,
      description: issue.remediation ?? issue.title,
      category: issue.category,
      source: issue.source,
      file: issue.locations[0]?.file,
      line: issue.locations[0]?.line,
      correctionContext: buildCorrectionContext(issue),
    })),
  };
}

function serializeScanPayload(payload: ReturnType<typeof createScanPayload>, format: "json" | "text"): unknown {
  if (format === "text") {
    return {
      summary: `Curatrix found ${payload.summary.totalIssues} issue(s) in ${payload.project.name}.`,
      result: payload,
    };
  }
  return payload;
}

function selectIssues(issues: Issue[], issueIds?: string[]): Issue[] {
  if (issueIds?.length) {
    return issues.filter((issue) => issueIds.includes(issue.id) || issueIds.includes(issue.fingerprint));
  }
  return issues.filter((issue) => issue.fixAvailability !== "none" || Boolean(issue.patch));
}

function buildCorrectionContext(issue: Issue) {
  return {
    type: correctionType(issue),
    action: correctionAction(issue),
    reasoning: correctionReasoning(issue),
    confidence: Math.min(0.99, Math.max(0.5, Number(issue.confidence.toFixed(2)))),
  };
}

function correctionType(issue: Issue): "dependency-update" | "config-patch" | "code-patch" | "manual-review" {
  if (issue.ruleId.startsWith("deps.")) {
    return "dependency-update";
  }
  if (issue.patch || /\.(js|ts|jsx|tsx|py|mjs|cjs)\b/.test(issue.locations[0]?.file ?? "")) {
    return "code-patch";
  }
  if (issue.fixAvailability === "apply" || issue.fixAvailability === "preview") {
    return "config-patch";
  }
  return "manual-review";
}

function correctionAction(issue: Issue): string {
  const remediation = issue.remediation?.trim();
  if (remediation) {
    const npmInstallMatch = remediation.match(/npm install\s+[^\n]+/i);
    if (npmInstallMatch) {
      return npmInstallMatch[0];
    }
    return remediation;
  }

  switch (issue.ruleId) {
    case "infra.docker.missing-user":
      return "Add a non-root USER line to the Dockerfile.";
    case "secrets.env-not-ignored":
      return "Add .env to .gitignore.";
    case "ai.open-bind-address":
      return "Bind the service to 127.0.0.1 instead of 0.0.0.0.";
    default:
      return "Review this finding and apply the safest targeted fix.";
  }
}

function correctionReasoning(issue: Issue): string {
  const packageEvidence = issue.evidence.find((entry) => entry.label === "package" || entry.label === "version")?.value;
  if (issue.ruleId === "deps.provider-vulnerability" || issue.ruleId === "deps.transitive-cve") {
    return `I recommend updating ${packageEvidence ?? "this dependency"} because the current version is tied to a reported vulnerability and the safer version reduces known risk.`;
  }
  if (issue.ruleId === "deps.suspicious-install-script") {
    return "I recommend reviewing this install script because it contains commands that commonly download, decode, or execute risky payloads during install.";
  }
  if (issue.ruleId === "ai.unsafe-exec") {
    return "I recommend removing this dynamic execution path because it can let untrusted input run code directly.";
  }
  if (issue.remediation) {
    return toHumanReasoning(issue.remediation);
  }
  return `I recommend fixing this because ${issue.why.charAt(0).toLowerCase()}${issue.why.slice(1)}`;
}

async function validateRootDir(rootDir: string) {
  try {
    await access(rootDir);
    return undefined;
  } catch {
    return errorResponse(`Path does not exist: ${rootDir}`);
  }
}

function successResponse(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function errorResponse(message: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ error: message }, null, 2),
      },
    ],
    isError: true,
  };
}

function toHumanReasoning(input: string): string {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return "I made this change because it reduces risk without making a broad or surprising modification.";
  }
  const sentence = trimmed.endsWith(".") ? trimmed : `${trimmed}.`;
  if (/^i\s+/i.test(sentence)) {
    return sentence;
  }
  return `I made this change because ${sentence.charAt(0).toLowerCase()}${sentence.slice(1)}`;
}

function isMainModule(moduleUrl: string): boolean {
  return process.argv[1] ? path.resolve(process.argv[1]) === path.resolve(fileURLToPath(moduleUrl)) : false;
}
