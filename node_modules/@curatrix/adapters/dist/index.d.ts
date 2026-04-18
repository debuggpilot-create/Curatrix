import type { AiRiskAnalyzer, McpToolAdapter, PackageVulnProvider, ProviderContext, VulnerabilityRecord } from "@curatrix/core";
export * from "./osv-provider.js";
export declare class NullVulnerabilityProvider implements PackageVulnProvider {
    readonly name = "null-provider";
    getVulnerabilities(_packageNames: string[], _context: ProviderContext): Promise<VulnerabilityRecord[]>;
}
export declare class ReservedAiRiskAnalyzer implements AiRiskAnalyzer {
    readonly name = "reserved-ai-analyzer";
    analyze(_input: string): Promise<string>;
}
export declare class ReservedMcpToolAdapter implements McpToolAdapter {
    readonly name = "reserved-mcp-adapter";
    invoke(_tool: string, _payload: unknown): Promise<unknown>;
}
