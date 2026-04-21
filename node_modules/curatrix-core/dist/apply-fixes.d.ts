import type { Issue, PackageVulnProvider } from "./types.js";
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
export declare function applyFixes({ rootDir, issues, autoConfirm, vulnerabilityProvider }: ApplyFixesOptions): Promise<ApplyFixesResult>;
export {};
