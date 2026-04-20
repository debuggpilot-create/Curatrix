import type { Issue, ScanResult } from "@curatrix/core";

const ansi = {
  reset: "\u001b[0m",
  cyan: "\u001b[36m",
  yellow: "\u001b[33m",
  magenta: "\u001b[35m",
  green: "\u001b[32m",
};

export function outputResult(result: ScanResult, format: "text" | "json" | "markdown"): string {
  if (format === "json") {
    return `${JSON.stringify(result, null, 2)}\n`;
  }
  if (format === "markdown") {
    return renderMarkdownTable(result.issues);
  }
  return renderText(result);
}

export function renderText(result: ScanResult, useColor: boolean = false): string {
  const staticIssues = result.issues.filter((issue) => issue.source === "static");
  const aiIssues = result.issues.filter((issue) => issue.source === "ai");
  const lines: string[] = [];

  lines.push(`${color("cyan", useColor)}Curatrix scan for ${result.project.name}${color("reset", useColor)}`);
  lines.push(`Issues: ${result.summary.totalIssues}`);
  lines.push(`Severity counts: critical=${result.summary.bySeverity.critical}, high=${result.summary.bySeverity.high}, medium=${result.summary.bySeverity.medium}, low=${result.summary.bySeverity.low}`);
  if (result.artifacts.baselineDelta) {
    lines.push(`Baseline delta: new=${result.artifacts.baselineDelta.new}, resolved=${result.artifacts.baselineDelta.resolved}, unchanged=${result.artifacts.baselineDelta.unchanged}`);
  }
  lines.push("");
  appendSection(lines, "Static Findings", staticIssues, "yellow", useColor);
  if (aiIssues.length > 0) {
    lines.push("");
    appendSection(lines, "AI Findings", aiIssues, "magenta", useColor);
  }
  return `${lines.join("\n")}\n`;
}

export function renderMarkdownTable(issues: Issue[]): string {
  const lines = [
    "### 🛡️ Curatrix Security Scan Results",
    "",
    "| Severity | Rule ID | File | Description |",
    "| :--- | :--- | :--- | :--- |",
  ];

  if (issues.length === 0) {
    lines.push("| ✅ None | - | - | No findings detected |");
    return `${lines.join("\n")}\n`;
  }

  for (const issue of issues) {
    const location = issue.locations[0];
    const file = location ? `${location.file}${location.line ? `:${location.line}` : ""}` : "<unknown>";
    const description = typeof issue.depth === "number"
      ? `[Depth: ${issue.depth}] ${issue.title}`
      : issue.title;

    lines.push(`| ${severityLabel(issue.severity)} | ${escapeMarkdown(issue.ruleId)} | ${escapeMarkdown(file)} | ${escapeMarkdown(description)} |`);
  }

  return `${lines.join("\n")}\n`;
}

export function renderFixPreview(issue: Issue, patchPreview: string, useColor: boolean = false): string {
  return [
    `${color(issue.source === "ai" ? "magenta" : "yellow", useColor)}Fix Preview${color("reset", useColor)}`,
    `Issue: ${issue.id}`,
    `Title: ${issue.title}`,
    `Source: ${issue.source}`,
    issue.remediation ? `Remediation: ${issue.remediation}` : "",
    "",
    patchPreview,
    "",
  ].filter(Boolean).join("\n");
}

export function renderFixResult(
  issue: Issue,
  result: { applied: Array<{ issueId: string; summary: string }>; skipped: Array<{ issueId: string; reason: string }> },
  useColor: boolean = false,
): string {
  const lines = [`${color("green", useColor)}Fix Result${color("reset", useColor)}`, `Issue: ${issue.id}`, `Source: ${issue.source}`];
  for (const applied of result.applied) {
    lines.push(`Applied: ${applied.summary}`);
  }
  for (const skipped of result.skipped) {
    lines.push(`Skipped: ${skipped.reason}`);
  }
  return `${lines.join("\n")}\n`;
}

function appendSection(
  lines: string[],
  title: string,
  issues: Issue[],
  colorName: keyof typeof ansi,
  useColor: boolean,
): void {
  lines.push(`${color(colorName, useColor)}${title}${color("reset", useColor)}`);
  if (issues.length === 0) {
    lines.push("  None");
    return;
  }

  for (const issue of issues) {
    const location = issue.locations[0];
    const depthPrefix = typeof issue.depth === "number" ? `[Depth: ${issue.depth}] ` : "";
    lines.push(`[${issue.severity.toUpperCase()}] ${depthPrefix}${issue.title}`);
    lines.push(`  id: ${issue.id}`);
    lines.push(`  source: ${issue.source}`);
    lines.push(`  file: ${location?.file ?? "<unknown>"}${location?.line ? `:${location.line}` : ""}`);
    lines.push(`  why: ${issue.why}`);
    if (issue.remediation) {
      lines.push(`  remediation: ${issue.remediation}`);
    }
    if (issue.baselineStatus) {
      lines.push(`  baseline: ${issue.baselineStatus}`);
    }
    for (const evidence of issue.evidence) {
      lines.push(`  evidence: ${evidence.label}=${evidence.value}`);
    }
    lines.push("");
  }
}

function severityLabel(severity: Issue["severity"]): string {
  switch (severity) {
    case "critical":
      return "🔴 Critical";
    case "high":
      return "🟠 High";
    case "medium":
      return "🟡 Medium";
    case "low":
    default:
      return "🟢 Low";
  }
}

function escapeMarkdown(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function color(name: keyof typeof ansi, useColor: boolean): string {
  return useColor ? ansi[name] : "";
}
