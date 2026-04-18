import { createHash } from "node:crypto";
export function createFingerprint(input) {
    return createHash("sha256").update(input).digest("hex").slice(0, 16);
}
export function createIssueId(issue) {
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
export function emptySummary() {
    return {
        totalIssues: 0,
        bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
        byCategory: { dependencies: 0, secrets: 0, infrastructure: 0, "ai-agent": 0 },
    };
}
//# sourceMappingURL=types.js.map