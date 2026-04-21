export type Severity = "low" | "medium" | "high" | "critical";
export type Category = "dependencies" | "secrets" | "infrastructure" | "ai-agent";
export type IssueSource = "static" | "ai";
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
    source: IssueSource;
    fingerprint: string;
    remediation?: string;
    patch?: string;
    baselineStatus?: BaselineStatus;
    depth?: number;
    reputation?: {
        ageDays: number;
        authorPackageCount: number;
    };
    vexStatus?: "not_affected" | "fixed";
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
    packageVersion?: string;
    aliases?: string[];
}
export interface PackageVulnProvider {
    name: string;
    getVulnerabilities(packageNames: string[], context: ProviderContext): Promise<VulnerabilityRecord[]>;
    getPackageVersionVulnerabilities?(packages: Array<{
        name: string;
        version: string;
        depth?: number;
    }>, context: ProviderContext): Promise<VulnerabilityRecord[]>;
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
    enableAiAudit?: boolean;
    aiApiKey?: string;
}
export interface FixOptions {
    rootDir: string;
    apply: boolean;
    vulnerabilityProvider?: PackageVulnProvider;
}
export declare function createFingerprint(input: string): string;
export declare function createIssueId(issue: Omit<Issue, "id" | "fingerprint">): Pick<Issue, "id" | "fingerprint">;
export declare function emptySummary(): ScanSummary;
