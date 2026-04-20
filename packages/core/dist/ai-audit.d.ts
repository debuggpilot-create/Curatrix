import { type Issue } from "./types.js";
interface AiAuditOptions {
    rootDir: string;
    apiKey: string;
}
export declare function runAiAudit({ rootDir, apiKey }: AiAuditOptions): Promise<Issue[]>;
export {};
