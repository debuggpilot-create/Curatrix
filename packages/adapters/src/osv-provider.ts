import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import type { PackageVulnProvider, ProviderContext, Severity, VulnerabilityRecord } from "@curatrix/core";

interface OsvResponse {
  vulns?: Array<{
    id?: string;
    summary?: string;
    aliases?: string[];
    severity?: Array<{ type?: string; score?: string }>;
    database_specific?: { severity?: string };
  }>;
}

type OsvVulnerability = NonNullable<OsvResponse["vulns"]>[number];

interface CacheEntry {
  createdAt: string;
  records: VulnerabilityRecord[];
}

const OSV_ENDPOINT = "https://api.osv.dev/v1/query";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const TOKENS_PER_MINUTE = 60;
const REFILL_WINDOW_MS = 60 * 1000;

export class OsvVulnerabilityProvider implements PackageVulnProvider {
  public readonly name = "osv";

  private availableTokens = TOKENS_PER_MINUTE;
  private lastRefillAt = Date.now();

  public async getVulnerabilities(packageNames: string[], context: ProviderContext): Promise<VulnerabilityRecord[]> {
    const packageJsonPath = path.join(context.rootDir, "package.json");
    const versions = await this.readDependencyVersions(packageJsonPath);
    const records: VulnerabilityRecord[] = [];

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

  private async fetchPackage(packageName: string, version: string): Promise<VulnerabilityRecord[]> {
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

      const payload = (await response.json()) as OsvResponse;
      return (payload.vulns ?? []).map((vuln) => ({
        packageName,
        severity: normalizeSeverity(vuln),
        advisory: [vuln.id, vuln.summary, ...(vuln.aliases ?? [])].filter(Boolean).join(" | "),
      }));
    } catch {
      return [];
    }
  }

  private async readDependencyVersions(packageJsonPath: string): Promise<Map<string, string>> {
    try {
      const content = await fs.readFile(packageJsonPath, "utf8");
      const parsed = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      return new Map(Object.entries({ ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) }));
    } catch {
      return new Map();
    }
  }

  private async readCache(packageName: string, version: string): Promise<VulnerabilityRecord[] | undefined> {
    const target = cachePath(packageName, version);

    try {
      const stat = await fs.stat(target);
      if (Date.now() - stat.mtimeMs > CACHE_TTL_MS) {
        return undefined;
      }
      const content = await fs.readFile(target, "utf8");
      const parsed = JSON.parse(content) as CacheEntry;
      return parsed.records ?? [];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        console.warn(`[curatrix] Warning: OSV cache read failed for ${packageName}@${version}.`);
      }
      return undefined;
    }
  }

  private async writeCache(packageName: string, version: string, records: VulnerabilityRecord[]): Promise<void> {
    const target = cachePath(packageName, version);
    try {
      await fs.mkdir(path.dirname(target), { recursive: true });
      const entry: CacheEntry = { createdAt: new Date().toISOString(), records };
      await fs.writeFile(target, JSON.stringify(entry, null, 2), "utf8");
    } catch {
      console.warn(`[curatrix] Warning: OSV cache directory is unavailable; continuing without cache persistence.`);
    }
  }

  private async takeToken(): Promise<void> {
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

  private refillTokens(): void {
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

function cachePath(packageName: string, version: string): string {
  const safeName = packageName.replace(/[\\/:*?"<>|@]/g, "_");
  const safeVersion = version.replace(/[\\/:*?"<>|]/g, "_");
  return path.join(os.homedir(), ".curatrix", "cache", "osv", `${safeName}-${safeVersion}.json`);
}

function normalizeSeverity(vuln: OsvVulnerability): Severity {
  const fromDb = vuln.database_specific?.severity?.toLowerCase();
  if (fromDb === "critical" || fromDb === "high" || fromDb === "medium" || fromDb === "low") {
    return fromDb;
  }

  const score = vuln.severity?.find((entry: NonNullable<OsvVulnerability["severity"]>[number]) => entry.type?.toUpperCase() === "CVSS_V3")?.score ?? vuln.severity?.[0]?.score;
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
