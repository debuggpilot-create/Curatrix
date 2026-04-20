import os from "node:os";
import path from "node:path";
import { access } from "node:fs/promises";
import { readJsonFile } from "./fs.js";
import type { Severity } from "./types.js";

export interface CuratrixConfig {
  modules: {
    dependencies: boolean;
    secrets: boolean;
    infrastructure: boolean;
    aiAgent: boolean;
  };
  severityOverrides: Record<string, Severity>;
  baselineDir: string;
  ignoredRuleIds: string[];
  maxDepth: number;
  vexFile?: string;
}

interface ConfigFileShape {
  modules?: {
    dependencies?: boolean;
    secrets?: boolean;
    infrastructure?: boolean;
    aiAgent?: boolean;
  };
  severityOverrides?: Record<string, string>;
  baselineDir?: string;
  maxDepth?: number;
  vexFile?: string;
}

const DEFAULT_CONFIG: CuratrixConfig = {
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

export async function loadCuratrixConfig(rootDir: string): Promise<CuratrixConfig> {
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

async function safeReadConfig(target: string): Promise<ConfigFileShape> {
  try {
    return (await readJsonFile<ConfigFileShape>(target)) ?? {};
  } catch {
    return {};
  }
}

async function safeReadIgnore(target: string): Promise<string[]> {
  try {
    const parsed = await readJsonFile<unknown>(target);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function sanitizeOverrides(overrides: Record<string, string> | undefined): Record<string, Severity> {
  if (!overrides) {
    return {};
  }

  const result: Record<string, Severity> = {};
  for (const [ruleId, severity] of Object.entries(overrides)) {
    if (severity === "low" || severity === "medium" || severity === "high" || severity === "critical") {
      result[ruleId] = severity;
    }
  }
  return result;
}

async function warnIfDirectoryMissing(target: string, label: string): Promise<void> {
  try {
    await access(target);
  } catch {
    console.warn(`[curatrix] Warning: ${label} directory ${target} is missing; using in-memory/default behavior.`);
  }
}

function sanitizeDepth(value: number): number {
  if (!Number.isFinite(value)) {
    return Number.POSITIVE_INFINITY;
  }
  if (value < 0) {
    return 0;
  }
  return Math.floor(value);
}

function sanitizeVexFile(value: string | undefined): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}
