import type { Issue, ScanResult } from "@curatrix/core";
export declare function outputResult(result: ScanResult, format: "text" | "json" | "markdown"): string;
export declare function renderText(result: ScanResult, useColor?: boolean): string;
export declare function renderMarkdownTable(issues: Issue[]): string;
export declare function renderFixPreview(issue: Issue, patchPreview: string, useColor?: boolean): string;
export declare function renderFixResult(issue: Issue, result: {
    applied: Array<{
        issueId: string;
        summary: string;
    }>;
    skipped: Array<{
        issueId: string;
        reason: string;
    }>;
}, useColor?: boolean): string;
