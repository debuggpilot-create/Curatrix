import path from "node:path";
import process from "node:process";
import { promises as fs } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Issue, PackageVulnProvider } from "./types.js";
import { applyFix, createFixPlan } from "./scan.js";

const execFileAsync = promisify(execFile);

interface ApplyFixesOptions {
  rootDir: string;
  issues: Issue[];
  autoConfirm: boolean;
  vulnerabilityProvider?: PackageVulnProvider;
}

export interface ApplyFixesResult {
  applied: Array<{ issueId: string; summary: string }>;
  skipped: Array<{ issueId: string; reason: string }>;
  changes?: Array<{
    issueId: string;
    file: string;
    changeType: "dependency-update" | "config-patch" | "code-patch";
    oldValue?: string;
    newValue?: string;
    diff?: string;
    reasoning: string;
  }>;
}

export async function applyFixes({ rootDir, issues, autoConfirm, vulnerabilityProvider }: ApplyFixesOptions): Promise<ApplyFixesResult> {
  const applied: ApplyFixesResult["applied"] = [];
  const skipped: ApplyFixesResult["skipped"] = [];
  const changes: NonNullable<ApplyFixesResult["changes"]> = [];

  for (const issue of issues) {
    const shouldApply = autoConfirm || await promptForConfirmation(issue);
    if (!shouldApply) {
      skipped.push({ issueId: issue.id, reason: "User declined apply." });
      continue;
    }

    if (issue.patch) {
      const patchChange = buildPatchChange(issue);
      const patchApplied = await applyUnifiedPatch(rootDir, issue);
      if (patchApplied) {
        applied.push({ issueId: issue.id, summary: issue.remediation ?? "Applied AI-generated patch." });
        if (patchChange) {
          changes.push(patchChange);
        }
      } else {
        skipped.push({ issueId: issue.id, reason: "Patch could not be applied cleanly." });
      }
      continue;
    }

    const npmInstallCommand = extractNpmInstall(issue.remediation);
    if (npmInstallCommand) {
      await execFileAsync("npm", npmInstallCommand, { cwd: rootDir });
      applied.push({ issueId: issue.id, summary: `Ran npm ${npmInstallCommand.join(" ")}` });
      changes.push({
        issueId: issue.id,
        file: "package.json",
        changeType: "dependency-update",
        oldValue: extractCurrentDependencyFromIssue(issue),
        newValue: npmInstallCommand.slice(1).join(" "),
        reasoning: toHumanReasoning(issue.remediation ?? `I updated this dependency because ${issue.title.toLowerCase()}.`),
      });
      continue;
    }

    try {
      const plan = await createFixPlan(rootDir, issue.id, { vulnerabilityProvider });
      const planChanges = await buildPlanChanges(rootDir, issue, plan.patchPreview);
      await backupIssueTargets(rootDir, issue);
      await applyFix({ rootDir, issueId: issue.id, apply: true, vulnerabilityProvider });
      applied.push({ issueId: issue.id, summary: plan.summary });
      changes.push(...planChanges);
    } catch (error) {
      skipped.push({
        issueId: issue.id,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return { applied, skipped, changes };
}

async function applyUnifiedPatch(rootDir: string, issue: Issue): Promise<boolean> {
  const patchText = issue.patch;
  if (!patchText) {
    return false;
  }

  const relativeTargetMatch = patchText.match(/^\+\+\+\s+b\/(.+)$/m);
  if (!relativeTargetMatch) {
    return false;
  }

  const relativeTarget = relativeTargetMatch[1];
  const absoluteTarget = path.join(rootDir, relativeTarget);
  const original = await fs.readFile(absoluteTarget, "utf8");
  await backupFile(absoluteTarget, original);
  const next = applySimpleUnifiedPatch(original, patchText);
  if (typeof next !== "string") {
    return false;
  }

  await fs.writeFile(absoluteTarget, next, "utf8");
  return true;
}

async function backupIssueTargets(rootDir: string, issue: Issue): Promise<void> {
  for (const location of issue.locations) {
    const absoluteTarget = path.join(rootDir, location.file);
    try {
      const original = await fs.readFile(absoluteTarget, "utf8");
      await backupFile(absoluteTarget, original);
    } catch {
      continue;
    }
  }
}

async function backupFile(target: string, contents: string): Promise<void> {
  const backupPath = `${target}.bak`;
  await fs.writeFile(backupPath, contents, "utf8");
}

async function promptForConfirmation(issue: Issue): Promise<boolean> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return false;
  }

  const { createInterface } = await import("node:readline/promises");
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await readline.question(`Apply fix for ${issue.id} (${issue.title})? [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    readline.close();
  }
}

function extractNpmInstall(remediation: string | undefined): string[] | undefined {
  if (!remediation) {
    return undefined;
  }
  const match = remediation.match(/npm install\s+([^\n]+)/i);
  return match ? ["install", ...match[1].trim().split(/\s+/)] : undefined;
}

async function buildPlanChanges(rootDir: string, issue: Issue, patchPreview: string) {
  const file = issue.locations[0]?.file ?? "<unknown>";
  const absolutePath = path.join(rootDir, file);
  const oldValue = await safeReadFile(absolutePath);
  const changeType = inferChangeType(issue, patchPreview);

  return [{
    issueId: issue.id,
    file,
    changeType,
    oldValue: summarizeValue(oldValue),
    newValue: summarizeValue(extractPatchedContent(patchPreview)),
    diff: patchPreview,
    reasoning: toHumanReasoning(issue.remediation ?? `I updated this because ${issue.why.toLowerCase()}`),
  }] satisfies NonNullable<ApplyFixesResult["changes"]>;
}

function buildPatchChange(issue: Issue) {
  if (!issue.patch) {
    return undefined;
  }

  return {
    issueId: issue.id,
    file: extractPatchTarget(issue.patch) ?? issue.locations[0]?.file ?? "<unknown>",
    changeType: inferChangeType(issue, issue.patch),
    diff: issue.patch,
    reasoning: toHumanReasoning(issue.remediation ?? `I updated this because ${issue.why.toLowerCase()}`),
  } satisfies NonNullable<ApplyFixesResult["changes"]>[number];
}

function extractCurrentDependencyFromIssue(issue: Issue): string | undefined {
  const evidence = issue.evidence.find((entry) => entry.label === "version" || entry.label === "package");
  return evidence?.value;
}

function inferChangeType(issue: Issue, patchLikeText: string | undefined): "dependency-update" | "config-patch" | "code-patch" {
  if (issue.ruleId.startsWith("deps.") || /package\.json|package-lock\.json/.test(patchLikeText ?? "")) {
    return "dependency-update";
  }
  if (/\.(js|ts|jsx|tsx|py|mjs|cjs)\b/.test(issue.locations[0]?.file ?? "")) {
    return "code-patch";
  }
  return "config-patch";
}

function extractPatchTarget(patchText: string): string | undefined {
  return patchText.match(/^\+\+\+\s+b\/(.+)$/m)?.[1];
}

function extractPatchedContent(patchText: string): string | undefined {
  const afterLines = patchText
    .split(/\r?\n/)
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1));
  return afterLines.length > 0 ? afterLines.join("\n") : undefined;
}

async function safeReadFile(target: string): Promise<string | undefined> {
  try {
    return await fs.readFile(target, "utf8");
  } catch {
    return undefined;
  }
}

function summarizeValue(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const singleLine = value.replace(/\s+/g, " ").trim();
  return singleLine.length > 160 ? `${singleLine.slice(0, 157)}...` : singleLine;
}

function toHumanReasoning(input: string): string {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return "I applied this change because it reduces the security risk without changing more than necessary.";
  }

  const normalized = trimmed.endsWith(".") ? trimmed : `${trimmed}.`;
  if (/^i\s+/i.test(normalized)) {
    return normalized;
  }
  return `I applied this change because ${normalized.charAt(0).toLowerCase()}${normalized.slice(1)}`;
}

function applySimpleUnifiedPatch(original: string, patchText: string): string | false {
  const beforeLines = patchText
    .split(/\r?\n/)
    .filter((line) => line.startsWith("-") && !line.startsWith("---"))
    .map((line) => line.slice(1));
  const afterLines = patchText
    .split(/\r?\n/)
    .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
    .map((line) => line.slice(1));

  const beforeText = beforeLines.join("\n");
  const afterText = afterLines.join("\n");
  if (!original.includes(beforeText)) {
    return false;
  }
  return original.replace(beforeText, afterText);
}
