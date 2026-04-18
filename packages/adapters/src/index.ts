import type { AiRiskAnalyzer, McpToolAdapter, PackageVulnProvider, ProviderContext, VulnerabilityRecord } from "@curatrix/core";
export * from "./osv-provider.js";

export class NullVulnerabilityProvider implements PackageVulnProvider {
  public readonly name = "null-provider";

  public async getVulnerabilities(_packageNames: string[], _context: ProviderContext): Promise<VulnerabilityRecord[]> {
    return [];
  }
}

export class ReservedAiRiskAnalyzer implements AiRiskAnalyzer {
  public readonly name = "reserved-ai-analyzer";

  public async analyze(_input: string): Promise<string> {
    throw new Error("AI analysis is reserved for a future Curatrix phase and is disabled in MVP.");
  }
}

export class ReservedMcpToolAdapter implements McpToolAdapter {
  public readonly name = "reserved-mcp-adapter";

  public async invoke(_tool: string, _payload: unknown): Promise<unknown> {
    throw new Error("MCP transport is reserved for a future Curatrix phase and is disabled in MVP.");
  }
}
