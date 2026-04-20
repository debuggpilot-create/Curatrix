import path from "node:path";
import { createIssueId } from "./types.js";
import { listFiles, readTextIfExists, relative } from "./fs.js";
const OPENAI_URL = "https://api.openai.com/v1/responses";
const MAX_FILES = 12;
const MAX_FILE_CHARS = 3500;
export async function runAiAudit({ rootDir, apiKey }) {
    const files = await listFiles(rootDir);
    const candidateFiles = files.filter((file) => /\.(ts|js|py|md)$/i.test(file)).slice(0, MAX_FILES);
    if (candidateFiles.length === 0) {
        return [];
    }
    const payloadFiles = [];
    for (const file of candidateFiles) {
        const content = await readTextIfExists(file);
        if (!content || content.trim().length === 0) {
            continue;
        }
        payloadFiles.push({
            path: relative(rootDir, file),
            content: content.slice(0, MAX_FILE_CHARS),
        });
    }
    if (payloadFiles.length === 0) {
        return [];
    }
    try {
        const response = await fetch(OPENAI_URL, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${apiKey}`,
            },
            body: JSON.stringify({
                model: "gpt-5.2",
                text: {
                    format: {
                        type: "json_object",
                    },
                },
                input: [
                    {
                        role: "developer",
                        content: [
                            {
                                type: "input_text",
                                text: [
                                    "You are a security auditor. Return JSON only.",
                                    "Analyze the provided repository files for malware, prompt injection, and suspicious permissions.",
                                    "Return an object with a findings array.",
                                    "Each finding must include: ruleId, category, severity, title, why, file.",
                                    "Optionally include line, remediation, patch, and evidence.",
                                    "Allowed categories: malware, prompt_injection, suspicious_permissions.",
                                    "JSON only.",
                                ].join(" "),
                            },
                        ],
                    },
                    {
                        role: "user",
                        content: [
                            {
                                type: "input_text",
                                text: JSON.stringify({ rootDir, files: payloadFiles }, null, 2),
                            },
                        ],
                    },
                ],
            }),
        });
        if (!response.ok) {
            return [];
        }
        const data = (await response.json());
        const parsed = safeParseAudit(data.output_text);
        return parsed.findings.map((finding) => createAiIssue(finding, rootDir));
    }
    catch {
        return [];
    }
}
function safeParseAudit(text) {
    if (!text) {
        return { findings: [] };
    }
    try {
        const parsed = JSON.parse(text);
        return {
            findings: Array.isArray(parsed.findings) ? parsed.findings.filter(isAiAuditFinding) : [],
        };
    }
    catch {
        return { findings: [] };
    }
}
function isAiAuditFinding(finding) {
    if (!finding || typeof finding !== "object") {
        return false;
    }
    const candidate = finding;
    return typeof candidate.ruleId === "string"
        && typeof candidate.category === "string"
        && typeof candidate.severity === "string"
        && typeof candidate.title === "string"
        && typeof candidate.why === "string"
        && typeof candidate.file === "string";
}
function createAiIssue(finding, rootDir) {
    const category = mapAiCategory(finding.category);
    const issueBase = {
        ruleId: finding.ruleId,
        category,
        severity: finding.severity,
        confidence: 0.72,
        title: finding.title,
        why: finding.why,
        evidence: (finding.evidence ?? []).map((value) => ({ label: "ai", value })),
        locations: [{ file: normalizeLocation(rootDir, finding.file), line: finding.line }],
        fixAvailability: (finding.patch ? "preview" : "none"),
        source: "ai",
        remediation: finding.remediation,
        patch: finding.patch,
    };
    return {
        ...issueBase,
        ...createIssueId(issueBase),
    };
}
function mapAiCategory(value) {
    switch (value) {
        case "malware":
            return "secrets";
        case "suspicious_permissions":
            return "infrastructure";
        case "prompt_injection":
        default:
            return "ai-agent";
    }
}
function normalizeLocation(rootDir, file) {
    if (path.isAbsolute(file)) {
        return relative(rootDir, file);
    }
    return file.replace(/\\/g, "/");
}
//# sourceMappingURL=ai-audit.js.map