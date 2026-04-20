import { type Issue, type PackageVulnProvider } from "@curatrix/core";
interface ApplyFixesOptions {
    rootDir: string;
    issues: Issue[];
    autoConfirm: boolean;
    vulnerabilityProvider?: PackageVulnProvider;
}
export interface ApplyFixesResult {
    applied: Array<{
        issueId: string;
        summary: string;
    }>;
    skipped: Array<{
        issueId: string;
        reason: string;
    }>;
}
export declare function applyFixes({ rootDir, issues, autoConfirm, vulnerabilityProvider }: ApplyFixesOptions): Promise<ApplyFixesResult>;
export {};
