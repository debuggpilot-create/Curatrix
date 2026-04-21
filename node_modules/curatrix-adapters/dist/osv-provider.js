import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
const OSV_ENDPOINT = "https://api.osv.dev/v1/query";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const TOKENS_PER_MINUTE = 60;
const REFILL_WINDOW_MS = 60 * 1000;
export class OsvVulnerabilityProvider {
    name = "osv";
    availableTokens = TOKENS_PER_MINUTE;
    lastRefillAt = Date.now();
    async getVulnerabilities(packageNames, context) {
        const packageJsonPath = path.join(context.rootDir, "package.json");
        const versions = await this.readDependencyVersions(packageJsonPath);
        const records = [];
        for (const packageName of packageNames) {
            const version = versions.get(packageName);
            if (!version || /^(\*|latest|\^|~|>|<|=)/.test(version.trim())) {
                continue;
            }
            const cached = await this.readCache(packageName, version);
            if (cached) {
                records.push(...cached);
                continue;
            }
            const fetched = await this.fetchPackage(packageName, version);
            if (fetched.length > 0 || fetched.length === 0) {
                await this.writeCache(packageName, version, fetched);
            }
            records.push(...fetched);
        }
        return records;
    }
    async getPackageVersionVulnerabilities(packages, _context) {
        const records = [];
        for (const dependency of packages) {
            if (!dependency.version || /^(\*|latest|\^|~|>|<|=)/.test(dependency.version.trim())) {
                continue;
            }
            const cached = await this.readCache(dependency.name, dependency.version);
            if (cached) {
                records.push(...cached);
                continue;
            }
            const fetched = await this.fetchPackage(dependency.name, dependency.version);
            await this.writeCache(dependency.name, dependency.version, fetched);
            records.push(...fetched);
        }
        return records;
    }
    async fetchPackage(packageName, version) {
        await this.takeToken();
        try {
            const response = await fetch(OSV_ENDPOINT, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" }, version }),
            });
            if (!response.ok) {
                return [];
            }
            const payload = (await response.json());
            return (payload.vulns ?? []).map((vuln) => ({
                packageName,
                packageVersion: version,
                severity: normalizeSeverity(vuln),
                advisory: [vuln.id, vuln.summary, ...(vuln.aliases ?? [])].filter(Boolean).join(" | "),
                aliases: [vuln.id, ...(vuln.aliases ?? [])].filter((value) => Boolean(value)),
            }));
        }
        catch {
            return [];
        }
    }
    async readDependencyVersions(packageJsonPath) {
        try {
            const content = await fs.readFile(packageJsonPath, "utf8");
            const parsed = JSON.parse(content);
            return new Map(Object.entries({ ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) }));
        }
        catch {
            return new Map();
        }
    }
    async readCache(packageName, version) {
        const target = cachePath(packageName, version);
        try {
            const stat = await fs.stat(target);
            if (Date.now() - stat.mtimeMs > CACHE_TTL_MS) {
                return undefined;
            }
            const content = await fs.readFile(target, "utf8");
            const parsed = JSON.parse(content);
            return parsed.records ?? [];
        }
        catch (error) {
            if (error.code !== "ENOENT") {
                console.warn(`[curatrix] Warning: OSV cache read failed for ${packageName}@${version}.`);
            }
            return undefined;
        }
    }
    async writeCache(packageName, version, records) {
        const target = cachePath(packageName, version);
        try {
            await fs.mkdir(path.dirname(target), { recursive: true });
            const entry = { createdAt: new Date().toISOString(), records };
            await fs.writeFile(target, JSON.stringify(entry, null, 2), "utf8");
        }
        catch {
            console.warn(`[curatrix] Warning: OSV cache directory is unavailable; continuing without cache persistence.`);
        }
    }
    async takeToken() {
        this.refillTokens();
        if (this.availableTokens > 0) {
            this.availableTokens -= 1;
            return;
        }
        const waitMs = Math.max(0, REFILL_WINDOW_MS - (Date.now() - this.lastRefillAt));
        await new Promise((resolve) => setTimeout(resolve, waitMs));
        this.refillTokens();
        this.availableTokens = Math.max(0, this.availableTokens - 1);
    }
    refillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastRefillAt;
        if (elapsed < REFILL_WINDOW_MS) {
            return;
        }
        const refillCount = Math.floor(elapsed / REFILL_WINDOW_MS);
        this.availableTokens = Math.min(TOKENS_PER_MINUTE, this.availableTokens + refillCount * TOKENS_PER_MINUTE);
        this.lastRefillAt = now;
    }
}
function cachePath(packageName, version) {
    const safeName = packageName.replace(/[\\/:*?"<>|@]/g, "_");
    const safeVersion = version.replace(/[\\/:*?"<>|]/g, "_");
    return path.join(os.homedir(), ".curatrix", "cache", "osv", `${safeName}-${safeVersion}.json`);
}
function normalizeSeverity(vuln) {
    const fromDb = vuln.database_specific?.severity?.toLowerCase();
    if (fromDb === "critical" || fromDb === "high" || fromDb === "medium" || fromDb === "low") {
        return fromDb;
    }
    const score = vuln.severity?.find((entry) => entry.type?.toUpperCase() === "CVSS_V3")?.score ?? vuln.severity?.[0]?.score;
    if (!score) {
        return "medium";
    }
    const numeric = Number.parseFloat(score.split("/").pop() ?? score);
    if (Number.isNaN(numeric)) {
        return "medium";
    }
    if (numeric >= 9) {
        return "critical";
    }
    if (numeric >= 7) {
        return "high";
    }
    if (numeric >= 4) {
        return "medium";
    }
    return "low";
}
//# sourceMappingURL=osv-provider.js.map