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
}
export declare function loadCuratrixConfig(rootDir: string): Promise<CuratrixConfig>;
