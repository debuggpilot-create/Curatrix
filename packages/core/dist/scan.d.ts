import { type FixOptions, type FixPlan, type ScanOptions, type ScanResult } from "./types.js";
export declare function scanProject(options: ScanOptions): Promise<ScanResult>;
export declare function saveBaseline(rootDir: string, result: ScanResult): Promise<string>;
export declare function compareWithBaseline(rootDir: string, result: ScanResult): Promise<ScanResult>;
export declare function createFixPlan(rootDir: string, issueId: string, options?: {
    vulnerabilityProvider?: ScanOptions["vulnerabilityProvider"];
}): Promise<FixPlan>;
export declare function applyFix(options: FixOptions & {
    issueId: string;
}): Promise<FixPlan>;
