import os from "node:os";
import path from "node:path";
import { access } from "node:fs/promises";
import { readJsonFile } from "./fs.js";
const DEFAULT_CONFIG = {
    modules: {
        dependencies: true,
        secrets: true,
        infrastructure: true,
        aiAgent: true,
    },
    severityOverrides: {},
    baselineDir: path.join(os.homedir(), ".curatrix", "baselines"),
    ignoredRuleIds: [],
    maxDepth: Number.POSITIVE_INFINITY,
    vexFile: undefined,
};
export async function loadCuratrixConfig(rootDir) {
    const globalPath = path.join(os.homedir(), ".curatrix", "config.json");
    const projectPath = path.join(rootDir, ".curatrixrc.json");
    const ignorePath = path.join(rootDir, ".curatrixignore.json");
    await warnIfDirectoryMissing(path.dirname(globalPath), "global config");
    await warnIfDirectoryMissing(path.dirname(DEFAULT_CONFIG.baselineDir), "baseline");
    const globalConfig = await safeReadConfig(globalPath);
    const projectConfig = await safeReadConfig(projectPath);
    const ignoredRuleIds = await safeReadIgnore(ignorePath);
    const mergedModules = {
        ...DEFAULT_CONFIG.modules,
        ...(globalConfig.modules ?? {}),
        ...(projectConfig.modules ?? {}),
    };
    return {
        modules: mergedModules,
        severityOverrides: {
            ...DEFAULT_CONFIG.severityOverrides,
            ...sanitizeOverrides(globalConfig.severityOverrides),
            ...sanitizeOverrides(projectConfig.severityOverrides),
        },
        baselineDir: projectConfig.baselineDir ?? globalConfig.baselineDir ?? DEFAULT_CONFIG.baselineDir,
        ignoredRuleIds,
        maxDepth: sanitizeDepth(projectConfig.maxDepth ?? globalConfig.maxDepth ?? DEFAULT_CONFIG.maxDepth),
        vexFile: sanitizeVexFile(projectConfig.vexFile ?? globalConfig.vexFile),
    };
}
async function safeReadConfig(target) {
    try {
        return (await readJsonFile(target)) ?? {};
    }
    catch {
        return {};
    }
}
async function safeReadIgnore(target) {
    try {
        const parsed = await readJsonFile(target);
        return Array.isArray(parsed) ? parsed.filter((item) => typeof item === "string") : [];
    }
    catch {
        return [];
    }
}
function sanitizeOverrides(overrides) {
    if (!overrides) {
        return {};
    }
    const result = {};
    for (const [ruleId, severity] of Object.entries(overrides)) {
        if (severity === "low" || severity === "medium" || severity === "high" || severity === "critical") {
            result[ruleId] = severity;
        }
    }
    return result;
}
async function warnIfDirectoryMissing(target, label) {
    try {
        await access(target);
    }
    catch {
        console.warn(`[curatrix] Warning: ${label} directory ${target} is missing; using in-memory/default behavior.`);
    }
}
function sanitizeDepth(value) {
    if (!Number.isFinite(value)) {
        return Number.POSITIVE_INFINITY;
    }
    if (value < 0) {
        return 0;
    }
    return Math.floor(value);
}
function sanitizeVexFile(value) {
    return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}
//# sourceMappingURL=config.js.map