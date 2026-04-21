export * from "./osv-provider.js";
export class NullVulnerabilityProvider {
    name = "null-provider";
    async getVulnerabilities(_packageNames, _context) {
        return [];
    }
}
export class ReservedAiRiskAnalyzer {
    name = "reserved-ai-analyzer";
    async analyze(_input) {
        throw new Error("AI analysis is reserved for a future Curatrix phase and is disabled in MVP.");
    }
}
export class ReservedMcpToolAdapter {
    name = "reserved-mcp-adapter";
    async invoke(_tool, _payload) {
        throw new Error("MCP transport is reserved for a future Curatrix phase and is disabled in MVP.");
    }
}
//# sourceMappingURL=index.js.map