import { createHash } from "node:crypto";

export type Severity = "low" | "medium" | "high" | "critical";
export type Category = "dependencies" | "secrets" | "infrastructure" | "ai-agent";
export type FixAvailability = "none" | "preview" | "apply";
export type FixRiskLevel = "low" | "medium" | "high";
export type BaselineStatus = "new" | "resolved" | "unchanged";

export interface Evidence {
  label: string;
  value: string;
}

export interface Location {
  file: string;
  line?: number;
}

export interface Issue {
  id: string;
  ruleId: string;
  category: Category;
  severity: Severity;
  confidence: number;
  title: string;
  why: string;
  evidence: Evidence[];
  locations: Location[];
  fixAvailability: FixAvailability;
  source: string;
  fingerprint: string;
  baselineStatus?: BaselineStatus;
}

export interface FixPlan {
  issueId: string;
  fixType: string;
  summary: string;
  patchPreview: string;
  riskLevel: FixRiskLevel;
  reversible: boolean;
  requiresReview: boolean;
  applySteps: string[];
}

export interface ScanSummary {
  totalIssues: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<Category, number>;
}

export interface BaselineDeltaSummary {
  new: number;
  resolved: number;
  unchanged: number;
}

export interface ScanResult {
  project: {
    name: string;
    root: string;
  };
  config?: {
    modules: {
      deps: boolean;
      secrets: boolean;
      infra: boolean;
      aiAgent: boolean;
    };
    ignoredRules: string[];
    severityOverrides: Record<string, string>;
  };
  targets: string[];
  issues: Issue[];
  summary: ScanSummary;
  policyOutcome: {
    passed: boolean;
    failingSeverity?: Severity;
  };
  timings: {
    startedAt: string;
    completedAt: string;
    durationMs: number;
  };
  artifacts: {
    baselineDelta?: BaselineDeltaSummary;
  };
  featureFlags: string[];
  redactionNotices: string[];
}

export interface BaselineSnapshot {
  projectRoot: string;
  createdAt: string;
  fingerprints: string[];
}

export interface ProviderContext {
  rootDir: string;
}

export interface VulnerabilityRecord {
  packageName: string;
  severity: Severity;
  advisory: string;
}

export interface PackageVulnProvider {
  name: string;
  getVulnerabilities(packageNames: string[], context: ProviderContext): Promise<VulnerabilityRecord[]>;
}

export interface AiRiskAnalyzer {
  name: string;
  analyze(input: string): Promise<string>;
}

export interface McpToolAdapter {
  name: string;
  invoke(tool: string, payload: unknown): Promise<unknown>;
}

export interface ScanOptions {
  rootDir: string;
  ci?: boolean;
  vulnerabilityProvider?: PackageVulnProvider;
}

export interface FixOptions {
  rootDir: string;
  apply: boolean;
  vulnerabilityProvider?: PackageVulnProvider;
}

export function createFingerprint(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

export function createIssueId(issue: Omit<Issue, "id" | "fingerprint">): Pick<Issue, "id" | "fingerprint"> {
  const fingerprint = createFingerprint([
    issue.ruleId,
    issue.locations.map((location) => `${location.file}:${location.line ?? 0}`).join("|"),
    issue.title,
    issue.why,
  ].join("::"));

  return {
    id: fingerprint,
    fingerprint,
  };
}

export function emptySummary(): ScanSummary {
  return {
    totalIssues: 0,
    bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
    byCategory: { dependencies: 0, secrets: 0, infrastructure: 0, "ai-agent": 0 },
  };
}
