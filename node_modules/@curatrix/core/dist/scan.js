import path from "node:path";
import { promises as fs } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runAiAudit } from "./ai-audit.js";
import { createIssueId, emptySummary } from "./types.js";
import { loadCuratrixConfig } from "./config.js";
import { ensureDirectory, listFiles, pathExists, readJsonFile, readTextIfExists, relative, writeText } from "./fs.js";
const execFileAsync = promisify(execFile);
const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
export async function scanProject(options) {
    const startedAtMs = Date.now();
    const startedAt = new Date(startedAtMs).toISOString();
    const rootDir = path.resolve(options.rootDir);
    const config = await loadCuratrixConfig(rootDir);
    const vexEntries = await loadVexEntries(rootDir, config);
    const files = await listFiles(rootDir);
    const packageIssues = config.modules.dependencies ? await scanDependencies(rootDir, files, options, config, vexEntries) : [];
    const secretIssues = config.modules.secrets ? await scanSecrets(rootDir, files) : [];
    const infraIssues = config.modules.infrastructure ? await scanInfrastructure(rootDir, files) : [];
    const aiIssues = config.modules.aiAgent ? await scanAiAgent(rootDir, files) : [];
    const semanticIssues = options.enableAiAudit && options.aiApiKey ? await runAiAudit({ rootDir, apiKey: options.aiApiKey }) : [];
    const issues = applyConfigToIssues([...packageIssues, ...secretIssues, ...infraIssues, ...aiIssues], config)
        .map(finalizeIssue)
        .concat(applyConfigToAiIssues(semanticIssues, config))
        .sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.fingerprint.localeCompare(b.fingerprint));
    const summary = emptySummary();
    for (const issue of issues) {
        summary.totalIssues += 1;
        summary.bySeverity[issue.severity] += 1;
        summary.byCategory[issue.category] += 1;
    }
    const completedAtMs = Date.now();
    return {
        project: {
            name: path.basename(rootDir),
            root: rootDir,
        },
        config: {
            modules: {
                deps: config.modules.dependencies,
                secrets: config.modules.secrets,
                infra: config.modules.infrastructure,
                aiAgent: config.modules.aiAgent,
            },
            ignoredRules: [...config.ignoredRuleIds],
            severityOverrides: { ...config.severityOverrides },
        },
        targets: [rootDir],
        issues,
        summary,
        policyOutcome: {
            passed: !issues.some((issue) => issue.severity === "high" || issue.severity === "critical"),
            failingSeverity: issues.find((issue) => issue.severity === "critical")?.severity ?? issues.find((issue) => issue.severity === "high")?.severity,
        },
        timings: {
            startedAt,
            completedAt: new Date(completedAtMs).toISOString(),
            durationMs: completedAtMs - startedAtMs,
        },
        artifacts: {},
        featureFlags: ["local-only", "review-first-fixes", ...(options.enableAiAudit ? ["ai-audit"] : [])],
        redactionNotices: ["Sensitive values are partially redacted in evidence output."],
    };
}
async function scanDependencies(rootDir, files, options, config, vexEntries) {
    const packageJsonPath = path.join(rootDir, "package.json");
    const packageJson = await readJsonFile(packageJsonPath);
    if (!packageJson) {
        return [];
    }
    const issues = [];
    const directDeps = {
        ...(packageJson.dependencies ?? {}),
        ...(packageJson.devDependencies ?? {}),
    };
    const packageText = (await readTextIfExists(packageJsonPath)) ?? "";
    const resolvedDependencies = await resolveNodeDependencies(rootDir, directDeps, config.maxDepth);
    for (const [name, version] of Object.entries(directDeps)) {
        if (/^(\*|latest|\^|~)/.test(version.trim())) {
            issues.push({
                ruleId: "deps.weak-version-range",
                category: "dependencies",
                severity: "medium",
                confidence: 0.95,
                title: `Dependency ${name} uses a weak version range`,
                why: "Floating or weak ranges reduce reproducibility and make supply-chain drift harder to audit.",
                evidence: [{ label: "version", value: `${name}@${version}` }],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${name}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Pin ${name} to an explicit reviewed version instead of using ${version}.`,
            });
        }
    }
    const riskyScripts = ["preinstall", "install", "postinstall", "prepare"];
    for (const scriptName of riskyScripts) {
        const scriptValue = packageJson.scripts?.[scriptName];
        if (scriptValue) {
            issues.push({
                ruleId: "deps.risky-lifecycle-script",
                category: "dependencies",
                severity: "high",
                confidence: 0.9,
                title: `Lifecycle script ${scriptName} is enabled`,
                why: "Install-time scripts increase the attack surface and are a common path for supply-chain abuse.",
                evidence: [{ label: scriptName, value: scriptValue }],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${scriptName}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Review whether the ${scriptName} lifecycle hook is necessary and remove or sandbox it if possible.`,
            });
            if (containsSuspiciousInstallScript(scriptValue)) {
                issues.push({
                    ruleId: "deps.suspicious-install-script",
                    category: "dependencies",
                    severity: "critical",
                    confidence: 0.94,
                    title: `Lifecycle script ${scriptName} contains suspicious install behavior`,
                    why: "Install-time commands that fetch, decode, or execute shell payloads are a common supply-chain compromise pattern.",
                    evidence: [{ label: scriptName, value: scriptValue }],
                    locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${scriptName}\"`) }],
                    fixAvailability: "none",
                    source: "static",
                    remediation: "Review install script for malicious payload before proceeding.",
                });
            }
        }
    }
    const hasLockfile = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"].some((file) => files.includes(path.join(rootDir, file)));
    if (!hasLockfile) {
        issues.push({
            ruleId: "deps.missing-lockfile",
            category: "dependencies",
            severity: "medium",
            confidence: 0.9,
            title: "Node manifest is missing a lockfile",
            why: "Lockfiles improve reproducibility and reduce unreviewed dependency drift.",
            evidence: [{ label: "manifest", value: "package.json present without package-lock.json, pnpm-lock.yaml, or yarn.lock" }],
            locations: [{ file: relative(rootDir, packageJsonPath), line: 1 }],
            fixAvailability: "none",
            source: "static",
            remediation: "Generate and commit a lockfile so dependency resolution stays reproducible.",
        });
    }
    const reputationRecords = await collectDependencyReputation(rootDir, resolvedDependencies);
    for (const dependency of resolvedDependencies) {
        const reputation = reputationRecords.get(`${dependency.name}@${dependency.version}`);
        if (!reputation) {
            continue;
        }
        if (reputation.ageDays < 14) {
            issues.push({
                ruleId: "deps.new-package-risk",
                category: "dependencies",
                severity: dependency.depth > 0 ? "medium" : "high",
                confidence: 0.78,
                title: `Package ${dependency.name}@${dependency.version} is very new`,
                why: "Very new packages deserve extra review because supply-chain attacks often rely on recently published packages.",
                evidence: [{ label: "ageDays", value: String(reputation.ageDays) }],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${dependency.name}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Review the provenance and necessity of ${dependency.name}@${dependency.version} before adoption.`,
                depth: dependency.depth,
                reputation: {
                    ageDays: reputation.ageDays,
                    authorPackageCount: reputation.authorPackageCount,
                },
            });
        }
        if (reputation.authorPackageCount > 0 && reputation.authorPackageCount < 3) {
            issues.push({
                ruleId: "deps.unproven-author",
                category: "dependencies",
                severity: "medium",
                confidence: 0.65,
                title: `Package ${dependency.name}@${dependency.version} is maintained by an unproven author`,
                why: "Packages from authors with very limited publishing history deserve additional review before being trusted.",
                evidence: [{ label: "authorPackageCount", value: String(reputation.authorPackageCount) }],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${dependency.name}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Review the maintainer history and package provenance for ${dependency.name}@${dependency.version}.`,
                depth: dependency.depth,
                reputation: {
                    ageDays: reputation.ageDays,
                    authorPackageCount: reputation.authorPackageCount,
                },
            });
        }
        if (reputation.versionJumpSuspicious) {
            issues.push({
                ruleId: "deps.suspicious-version-bump",
                category: "dependencies",
                severity: "high",
                confidence: 0.72,
                title: `Package ${dependency.name}@${dependency.version} has a suspicious rapid major version jump`,
                why: "A rapid jump from 0.x to 1.x can indicate rushed or potentially malicious release activity and deserves validation.",
                evidence: [{ label: "package", value: `${dependency.name}@${dependency.version}` }],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${dependency.name}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Validate the release history and changelog for ${dependency.name}@${dependency.version} before upgrading.`,
                depth: dependency.depth,
                reputation: {
                    ageDays: reputation.ageDays,
                    authorPackageCount: reputation.authorPackageCount,
                },
            });
        }
    }
    if (options.vulnerabilityProvider) {
        const usage = await discoverDependencyUsage(files, Object.keys(directDeps));
        const vulnerabilityInputs = resolvedDependencies.map((dependency) => ({
            name: dependency.name,
            version: dependency.version,
            depth: dependency.depth,
        }));
        const vulnerabilities = options.vulnerabilityProvider.getPackageVersionVulnerabilities
            ? await options.vulnerabilityProvider.getPackageVersionVulnerabilities(vulnerabilityInputs, { rootDir })
            : await options.vulnerabilityProvider.getVulnerabilities(Object.keys(directDeps), { rootDir });
        for (const vuln of vulnerabilities) {
            const dependency = resolvedDependencies.find((entry) => entry.name === vuln.packageName && (!vuln.packageVersion || entry.version === vuln.packageVersion));
            const depth = dependency?.depth ?? 0;
            const used = depth > 0 ? true : usage.has(vuln.packageName);
            const aliases = vuln.aliases ?? advisoryAliases(vuln.advisory);
            const vexStatus = resolveVexStatus(vexEntries, vuln.packageName, vuln.packageVersion, aliases);
            if (vexStatus === "not_affected") {
                continue;
            }
            issues.push({
                ruleId: depth > 0 ? "deps.transitive-cve" : "deps.provider-vulnerability",
                category: "dependencies",
                severity: used ? vuln.severity : downgradeSeverity(vuln.severity),
                confidence: 0.8,
                title: `Dependency ${vuln.packageName}${vuln.packageVersion ? `@${vuln.packageVersion}` : ""} has a provider-reported advisory`,
                why: depth > 0
                    ? `A transitive dependency at depth ${depth} carries a provider-reported advisory and should be reviewed through the full dependency chain.`
                    : used
                        ? "The vulnerable package is referenced in code, increasing practical exposure."
                        : "The package is declared but not referenced in project code, so severity is downgraded until usage is confirmed.",
                evidence: [
                    { label: "advisory", value: vuln.advisory },
                    { label: "package", value: `${vuln.packageName}${vuln.packageVersion ? `@${vuln.packageVersion}` : ""}` },
                    { label: "usage", value: used ? "used in project files" : "no imports detected" },
                ],
                locations: [{ file: relative(rootDir, packageJsonPath), line: findLine(packageText, `\"${vuln.packageName}\"`) }],
                fixAvailability: "none",
                source: "static",
                remediation: `Upgrade or replace ${vuln.packageName} after reviewing the advisory and dependency usage.`,
                depth,
                vexStatus,
            });
        }
    }
    return issues;
}
async function discoverDependencyUsage(files, packageNames) {
    const used = new Set();
    const codeFiles = files.filter((file) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(file));
    for (const file of codeFiles) {
        const content = await readTextIfExists(file);
        if (!content) {
            continue;
        }
        for (const packageName of packageNames) {
            const escaped = escapeRegExp(packageName);
            const pattern = new RegExp(`(?:from\\s+["']${escaped}["']|require\\(\\s*["']${escaped}["']\\s*\\)|import\\(\\s*["']${escaped}["']\\s*\\))`);
            if (pattern.test(content)) {
                used.add(packageName);
            }
        }
    }
    return used;
}
async function resolveNodeDependencies(rootDir, directDeps, maxDepth) {
    const resolved = new Map();
    const lockfile = await readJsonFile(path.join(rootDir, "package-lock.json"));
    for (const [name, version] of Object.entries(directDeps)) {
        if (isConcreteVersion(version)) {
            resolved.set(`${name}@${version}`, { name, version, depth: 0, direct: true });
        }
    }
    if (!lockfile) {
        return [...resolved.values()].sort(compareResolvedDependencies);
    }
    if (lockfile.packages && Object.keys(lockfile.packages).length > 0) {
        collectFromPackageLockPackages(lockfile.packages, resolved, maxDepth);
    }
    else if (lockfile.dependencies) {
        collectFromPackageLockDependencies(lockfile.dependencies, resolved, 1, maxDepth);
    }
    return [...resolved.values()].sort(compareResolvedDependencies);
}
function collectFromPackageLockPackages(packages, resolved, maxDepth) {
    const queue = [{ packagePath: "", depth: 0 }];
    const visited = new Set();
    while (queue.length > 0) {
        const current = queue.shift();
        if (!current) {
            continue;
        }
        const marker = `${current.packagePath}:${current.depth}`;
        if (visited.has(marker)) {
            continue;
        }
        visited.add(marker);
        const entry = packages[current.packagePath];
        if (!entry?.dependencies) {
            continue;
        }
        for (const dependencyName of Object.keys(entry.dependencies)) {
            const packagePath = current.packagePath
                ? path.posix.join(current.packagePath.replace(/\\/g, "/"), "node_modules", dependencyName)
                : `node_modules/${dependencyName}`;
            const dependencyEntry = packages[packagePath];
            const depth = current.depth + 1;
            if (!dependencyEntry?.version || depth > maxDepth) {
                continue;
            }
            addResolvedDependency(resolved, dependencyName, dependencyEntry.version, depth);
            queue.push({ packagePath, depth });
        }
    }
}
function collectFromPackageLockDependencies(dependencies, resolved, depth, maxDepth) {
    if (depth > maxDepth) {
        return;
    }
    for (const [name, dependency] of Object.entries(dependencies)) {
        if (dependency.version) {
            addResolvedDependency(resolved, name, dependency.version, depth);
        }
        if (dependency.dependencies) {
            collectFromPackageLockDependencies(dependency.dependencies, resolved, depth + 1, maxDepth);
        }
    }
}
function addResolvedDependency(resolved, name, version, depth) {
    const key = `${name}@${version}`;
    const existing = resolved.get(key);
    if (!existing || depth < existing.depth) {
        resolved.set(key, { name, version, depth, direct: depth === 0 });
    }
}
function compareResolvedDependencies(a, b) {
    return a.depth - b.depth || a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
}
function isConcreteVersion(version) {
    return !/^(\*|latest|\^|~|>|<|=)/.test(version.trim());
}
function containsSuspiciousInstallScript(scriptValue) {
    const suspiciousPattern = /\b(?:curl|wget|bash|sh|eval|base64)\b|chmod\s+777/i;
    const obfuscationPattern = /Buffer\.from\(\s*['"`][^'"`]+['"`]\s*,\s*['"`](?:hex|base64)['"`]\s*\)\.toString\(/i;
    return suspiciousPattern.test(scriptValue) || obfuscationPattern.test(scriptValue);
}
async function collectDependencyReputation(rootDir, dependencies) {
    const reputation = new Map();
    for (const dependency of dependencies) {
        const record = await getPackageReputation(rootDir, dependency.name, dependency.version);
        if (record) {
            reputation.set(`${dependency.name}@${dependency.version}`, record);
        }
    }
    return reputation;
}
async function getPackageReputation(rootDir, pkgName, pkgVersion) {
    const cache = await readReputationCache(rootDir);
    const key = `${pkgName}@${pkgVersion}`;
    const cached = cache[key];
    if (cached && Date.now() - Date.parse(cached.cachedAt) < 24 * 60 * 60 * 1000) {
        return cached.record;
    }
    try {
        const response = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`);
        if (!response.ok) {
            return undefined;
        }
        const payload = await response.json();
        const publishedAt = payload.time?.[pkgVersion];
        const ageDays = publishedAt ? Math.max(0, Math.floor((Date.now() - Date.parse(publishedAt)) / (24 * 60 * 60 * 1000))) : Number.MAX_SAFE_INTEGER;
        const authorName = resolveAuthorName(payload, pkgVersion);
        const authorPackageCount = authorName ? (await fetchAuthorPackageCount(authorName)) ?? 3 : 3;
        const versionJumpSuspicious = isSuspiciousVersionJump(pkgVersion, payload.time ?? {});
        const record = {
            packageName: pkgName,
            packageVersion: pkgVersion,
            ageDays,
            authorPackageCount,
            versionJumpSuspicious,
        };
        cache[key] = { cachedAt: new Date().toISOString(), record };
        await writeReputationCache(rootDir, cache);
        return record;
    }
    catch {
        return undefined;
    }
}
function resolveAuthorName(payload, pkgVersion) {
    const versionEntry = payload.versions?.[pkgVersion];
    const versionAuthor = typeof versionEntry?.author === "string" ? versionEntry.author : versionEntry?.author?.name;
    if (versionAuthor) {
        return versionAuthor;
    }
    const versionMaintainer = versionEntry?.maintainers?.find((item) => item.name)?.name;
    if (versionMaintainer) {
        return versionMaintainer;
    }
    const rootAuthor = typeof payload.author === "string" ? payload.author : payload.author?.name;
    if (rootAuthor) {
        return rootAuthor;
    }
    return payload.maintainers?.find((item) => item.name)?.name;
}
async function fetchAuthorPackageCount(authorName) {
    try {
        const response = await fetch(`https://registry.npmjs.org/-/v1/search?text=maintainer:${encodeURIComponent(authorName)}&size=3`);
        if (!response.ok) {
            return undefined;
        }
        const payload = await response.json();
        return payload.total;
    }
    catch {
        return undefined;
    }
}
function isSuspiciousVersionJump(pkgVersion, timeMap) {
    if (!/^\d+\.\d+\.\d+/.test(pkgVersion)) {
        return false;
    }
    const [major] = pkgVersion.split(".");
    const currentMajor = Number.parseInt(major, 10);
    if (Number.isNaN(currentMajor) || currentMajor < 1) {
        return false;
    }
    let latestPreOnePublishedAt;
    const currentPublishedAt = Date.parse(timeMap[pkgVersion] ?? "");
    if (Number.isNaN(currentPublishedAt)) {
        return false;
    }
    for (const [version, timestamp] of Object.entries(timeMap)) {
        if (!/^\d+\.\d+\.\d+/.test(version)) {
            continue;
        }
        const versionMajor = Number.parseInt(version.split(".")[0] ?? "", 10);
        if (Number.isNaN(versionMajor) || versionMajor >= 1) {
            continue;
        }
        const publishedAt = Date.parse(timestamp);
        if (!Number.isNaN(publishedAt) && (latestPreOnePublishedAt === undefined || publishedAt > latestPreOnePublishedAt)) {
            latestPreOnePublishedAt = publishedAt;
        }
    }
    if (latestPreOnePublishedAt === undefined) {
        return false;
    }
    return currentPublishedAt - latestPreOnePublishedAt < 24 * 60 * 60 * 1000;
}
async function readReputationCache(rootDir) {
    const target = path.join(rootDir, ".curatrix", "cache", "reputation.json");
    try {
        return (await readJsonFile(target)) ?? {};
    }
    catch {
        console.warn(`[curatrix] Warning: reputation cache ${target} is unavailable or malformed; continuing without cache reuse.`);
        return {};
    }
}
async function writeReputationCache(rootDir, cache) {
    const target = path.join(rootDir, ".curatrix", "cache", "reputation.json");
    try {
        await writeText(target, JSON.stringify(cache, null, 2));
    }
    catch {
        console.warn(`[curatrix] Warning: reputation cache directory ${path.dirname(target)} is unavailable; continuing without cache persistence.`);
    }
}
async function loadVexEntries(rootDir, config) {
    const configuredPath = config.vexFile ? path.resolve(rootDir, config.vexFile) : path.join(rootDir, ".curatrix.vex.json");
    try {
        const payload = await readJsonFile(configuredPath);
        if (!payload?.vulnerabilities) {
            return [];
        }
        const productNames = new Map();
        for (const product of payload.product_tree?.full_product_names ?? []) {
            if (product.product_id && product.name) {
                productNames.set(product.product_id, product.name);
            }
        }
        const entries = [];
        for (const vulnerability of payload.vulnerabilities) {
            const cve = vulnerability.cve ?? vulnerability.cve_id;
            if (!cve) {
                continue;
            }
            for (const status of ["not_affected", "fixed"]) {
                for (const productId of vulnerability.product_status?.[status] ?? []) {
                    const component = productNames.get(productId) ?? productId;
                    entries.push({ cve, status, component });
                }
            }
        }
        return entries;
    }
    catch {
        return [];
    }
}
function resolveVexStatus(vexEntries, packageName, packageVersion, aliases) {
    const componentMatchers = [
        `${packageName}${packageVersion ? `@${packageVersion}` : ""}`.toLowerCase(),
        packageName.toLowerCase(),
    ];
    for (const alias of aliases) {
        const normalizedAlias = alias.toUpperCase();
        const match = vexEntries.find((entry) => entry.cve.toUpperCase() === normalizedAlias
            && componentMatchers.some((component) => entry.component.toLowerCase().includes(component)));
        if (match) {
            return match.status;
        }
    }
    return undefined;
}
function advisoryAliases(advisory) {
    return advisory.split("|").map((part) => part.trim()).filter((part) => /^CVE-/i.test(part));
}
async function scanSecrets(rootDir, files) {
    const issues = [];
    const patterns = [
        { ruleId: "secrets.aws-key", regex: /AKIA[0-9A-Z]{16}/g, title: "Possible AWS access key detected", severity: "critical" },
        { ruleId: "secrets.stripe-key", regex: /sk_(?:live|test)_[0-9A-Za-z]{16,}/g, title: "Possible Stripe secret key detected", severity: "critical" },
        { ruleId: "secrets.jwt", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}/g, title: "Possible JWT token detected", severity: "high" },
        { ruleId: "secrets.private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, title: "Private key material detected", severity: "critical" },
    ];
    for (const file of files) {
        const content = await readTextIfExists(file);
        if (!content) {
            continue;
        }
        for (const pattern of patterns) {
            for (const match of content.matchAll(pattern.regex)) {
                issues.push({
                    ruleId: pattern.ruleId,
                    category: "secrets",
                    severity: pattern.severity,
                    confidence: 0.98,
                    title: pattern.title,
                    why: "Secrets in tracked files can leak credentials and should be rotated or removed.",
                    evidence: [{ label: "match", value: redact(match[0]) }],
                    locations: [{ file: relative(rootDir, file), line: findLine(content, match[0]) }],
                    fixAvailability: "none",
                    source: "static",
                    remediation: "Remove the secret from the file, rotate the credential, and move it to a secure secret store.",
                });
            }
        }
        for (const token of content.match(/[A-Za-z0-9_\/-]{20,}/g) ?? []) {
            if (shannonEntropy(token) > 4.5 && !looksLikePath(token)) {
                issues.push({
                    ruleId: "secrets.high-entropy",
                    category: "secrets",
                    severity: "medium",
                    confidence: 0.65,
                    title: "High-entropy token detected",
                    why: "High-entropy strings can indicate embedded secrets and deserve review.",
                    evidence: [{ label: "token", value: redact(token) }],
                    locations: [{ file: relative(rootDir, file), line: findLine(content, token) }],
                    fixAvailability: "none",
                    source: "static",
                    remediation: "Review the token, remove it if it is sensitive, and store secrets outside tracked files.",
                });
                break;
            }
        }
    }
    const envPath = path.join(rootDir, ".env");
    const gitIgnorePath = path.join(rootDir, ".gitignore");
    if (await pathExists(envPath)) {
        const ignore = (await readTextIfExists(gitIgnorePath)) ?? "";
        if (!ignore.split(/\r?\n/).map((line) => line.trim()).includes(".env")) {
            issues.push({
                ruleId: "secrets.env-not-ignored",
                category: "secrets",
                severity: "high",
                confidence: 0.95,
                title: ".env exists but is not ignored by git",
                why: "Environment files often contain credentials and should be ignored to prevent accidental commits.",
                evidence: [{ label: "file", value: ".env present without matching .gitignore rule" }],
                locations: [{ file: ".gitignore", line: 1 }],
                fixAvailability: "apply",
                source: "static",
                remediation: "Add .env to .gitignore and verify no sensitive environment files are tracked.",
            });
        }
    }
    issues.push(...(await scanGitHistory(rootDir)));
    return dedupeIssues(issues);
}
async function scanGitHistory(rootDir) {
    const gitDir = path.join(rootDir, ".git");
    if (!(await pathExists(gitDir))) {
        return [];
    }
    const expressions = [
        { ruleId: "secrets.git-history.aws-key", pattern: "AKIA[0-9A-Z]{16}", title: "Git history contains a possible AWS access key" },
        { ruleId: "secrets.git-history.private-key", pattern: "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY", title: "Git history contains private key material" },
        { ruleId: "secrets.git-history.jwt", pattern: "eyJ[A-Za-z0-9_-]{10,}", title: "Git history contains a possible JWT token" },
    ];
    const issues = [];
    for (const expression of expressions) {
        try {
            const { stdout } = await execFileAsync("git", [
                "log",
                "--all",
                `-G${expression.pattern}`,
                "--pretty=format:%H%x09%an%x09%ad",
                "--date=short",
                "--name-only",
            ], { cwd: rootDir, maxBuffer: 1024 * 1024 * 5 });
            const lines = stdout.split(/\r?\n/).filter(Boolean);
            let currentMeta;
            for (const line of lines) {
                if (line.includes("\t")) {
                    const [hash, author, date] = line.split("\t");
                    currentMeta = { hash, author, date };
                    continue;
                }
                if (currentMeta) {
                    issues.push({
                        ruleId: expression.ruleId,
                        category: "secrets",
                        severity: "high",
                        confidence: 0.8,
                        title: expression.title,
                        why: "Secrets in git history remain recoverable even after deletion from the working tree.",
                        evidence: [
                            { label: "commit", value: currentMeta.hash },
                            { label: "author", value: currentMeta.author },
                            { label: "date", value: currentMeta.date },
                        ],
                        locations: [{ file: line }],
                        fixAvailability: "none",
                        source: "static",
                        remediation: "Purge the secret from git history if needed and rotate any affected credentials.",
                    });
                }
            }
        }
        catch {
            return issues;
        }
    }
    return dedupeIssues(issues);
}
async function scanInfrastructure(rootDir, files) {
    const issues = [];
    const dockerfiles = files.filter((file) => path.basename(file).startsWith("Dockerfile"));
    for (const dockerfile of dockerfiles) {
        const content = (await readTextIfExists(dockerfile)) ?? "";
        if (/FROM\s+[^\s]+:latest/i.test(content)) {
            issues.push({
                ruleId: "infra.docker.latest-tag",
                category: "infrastructure",
                severity: "medium",
                confidence: 0.95,
                title: "Dockerfile uses a floating latest tag",
                why: "Floating image tags make builds non-reproducible and can silently change runtime contents.",
                evidence: [{ label: "from", value: content.match(/FROM\s+.+/i)?.[0] ?? "FROM <unknown>" }],
                locations: [{ file: relative(rootDir, dockerfile), line: findLine(content, "FROM") }],
                fixAvailability: "none",
                source: "static",
                remediation: "Pin the base image to an explicit version or digest instead of relying on latest.",
            });
        }
        if (!/^USER\s+/m.test(content)) {
            issues.push({
                ruleId: "infra.docker.missing-user",
                category: "infrastructure",
                severity: "high",
                confidence: 0.92,
                title: "Dockerfile does not set a non-root USER",
                why: "Containers should drop root privileges explicitly to reduce impact from runtime compromise.",
                evidence: [{ label: "dockerfile", value: relative(rootDir, dockerfile) }],
                locations: [{ file: relative(rootDir, dockerfile), line: 1 }],
                fixAvailability: "apply",
                source: "static",
                remediation: "Add a non-root USER instruction to reduce container privilege at runtime.",
            });
        }
        if (/COPY\s+\.\s+\.([\s\S]*?)RUN\s+/i.test(content)) {
            issues.push({
                ruleId: "infra.docker.copy-before-run",
                category: "infrastructure",
                severity: "medium",
                confidence: 0.75,
                title: "Dockerfile copies the full build context before RUN steps",
                why: "Broad COPY before build steps hurts caching and can pull unintended files into the image context.",
                evidence: [{ label: "pattern", value: "COPY . . before RUN" }],
                locations: [{ file: relative(rootDir, dockerfile), line: findLine(content, "COPY . .") }],
                fixAvailability: "none",
                source: "static",
                remediation: "Copy only the files needed for each build step to improve cache safety and reduce image context.",
            });
        }
    }
    const yamlFiles = files.filter((file) => /(?:docker-compose|compose|\.github\/workflows\/.*\.ya?ml$|\.ya?ml$)/i.test(relative(rootDir, file)));
    for (const file of yamlFiles) {
        const content = (await readTextIfExists(file)) ?? "";
        const rel = relative(rootDir, file);
        if (/privileged:\s*true/i.test(content)) {
            issues.push({
                ruleId: "infra.privileged-container",
                category: "infrastructure",
                severity: "high",
                confidence: 0.93,
                title: "Infrastructure config enables privileged execution",
                why: "Privileged containers dramatically expand the blast radius of compromise.",
                evidence: [{ label: "setting", value: "privileged: true" }],
                locations: [{ file: rel, line: findLine(content, "privileged:") }],
                fixAvailability: "none",
                source: "static",
                remediation: "Remove privileged mode unless it is absolutely required and documented.",
            });
        }
        if (/echo\s+\$\{\{\s*secrets\./i.test(content)) {
            issues.push({
                ruleId: "infra.secret-logging",
                category: "infrastructure",
                severity: "high",
                confidence: 0.9,
                title: "Workflow logs a secret value directly",
                why: "Secrets printed in CI logs can leak credentials to build systems and reviewers.",
                evidence: [{ label: "pattern", value: "echo ${{ secrets.* }}" }],
                locations: [{ file: rel, line: findLine(content, "secrets.") }],
                fixAvailability: "none",
                source: "static",
                remediation: "Stop printing secret values in logs and replace them with masked status output.",
            });
        }
        if (rel.startsWith(".github/workflows/") && !/(npm\s+(test|run test)|pnpm\s+test|yarn\s+test)/i.test(content)) {
            issues.push({
                ruleId: "infra.workflow-missing-test-step",
                category: "infrastructure",
                severity: "medium",
                confidence: 0.72,
                title: "Workflow is missing a visible test step",
                why: "Basic build automation should exercise tests to catch regressions before deployment.",
                evidence: [{ label: "workflow", value: rel }],
                locations: [{ file: rel, line: 1 }],
                fixAvailability: "none",
                source: "static",
                remediation: "Add an explicit test step to the workflow so regressions are caught before release.",
            });
        }
    }
    return issues;
}
async function scanAiAgent(rootDir, files) {
    const issues = [];
    const aiFiles = files.filter((file) => {
        const rel = relative(rootDir, file);
        return /^(skills|plugins|prompts|memory)\//.test(rel) || /agent|prompt/i.test(path.basename(file));
    });
    for (const file of aiFiles) {
        const content = (await readTextIfExists(file)) ?? "";
        const rel = relative(rootDir, file);
        if (content.trim().length > 0 && /system prompt|assistant/i.test(content) && !(/<SYSTEM>/i.test(content) && /<USER>/i.test(content))) {
            issues.push({
                ruleId: "ai.prompt-missing-delimiters",
                category: "ai-agent",
                severity: "high",
                confidence: 0.82,
                title: "Prompt file is missing <SYSTEM>/<USER> delimiters",
                why: "Explicit delimiters reduce prompt injection risk and make trust boundaries clearer.",
                evidence: [{ label: "file", value: rel }],
                locations: [{ file: rel, line: 1 }],
                fixAvailability: "apply",
                source: "static",
                remediation: "Wrap the prompt with explicit SYSTEM and USER delimiters to preserve trust boundaries.",
            });
        }
        if (/systemPrompt\s*\+|messages?\.push\(\s*systemPrompt\s*\+|`[^`]*\$\{\s*(?:input|userInput|prompt)\s*\}[^`]*`/i.test(content)) {
            issues.push({
                ruleId: "ai.prompt-concatenation",
                category: "ai-agent",
                severity: "high",
                confidence: 0.84,
                title: "Prompt content is concatenated directly with user-controlled input",
                why: "Direct prompt concatenation blurs trust boundaries and raises prompt injection risk.",
                evidence: [{ label: "pattern", value: "direct system/user prompt concatenation" }],
                locations: [{ file: rel, line: 1 }],
                fixAvailability: "none",
                source: "static",
                remediation: "Separate trusted system instructions from user input instead of concatenating them directly.",
            });
        }
        if (/\b(?:eval|exec)\s*\(/i.test(content)) {
            const pattern = content.match(/\b(?:eval|exec)\s*\(/i)?.[0] ?? "eval(";
            issues.push({
                ruleId: "ai.unsafe-exec",
                category: "ai-agent",
                severity: "critical",
                confidence: 0.93,
                title: "Agent file uses eval/exec",
                why: "Dynamic execution primitives increase the chance of code injection and unsafe tool execution.",
                evidence: [{ label: "pattern", value: pattern }],
                locations: [{ file: rel, line: findLine(content, pattern) }],
                fixAvailability: "none",
                source: "static",
                remediation: "Replace eval/exec with an explicit allowlisted execution path or structured command dispatch.",
            });
        }
        if (/0\.0\.0\.0/.test(content)) {
            issues.push({
                ruleId: "ai.open-bind-address",
                category: "ai-agent",
                severity: "medium",
                confidence: 0.88,
                title: "Agent config exposes service on 0.0.0.0",
                why: "Binding to all interfaces is riskier than local-only defaults for development and agent control surfaces.",
                evidence: [{ label: "bind", value: "0.0.0.0" }],
                locations: [{ file: rel, line: findLine(content, "0.0.0.0") }],
                fixAvailability: "apply",
                source: "static",
                remediation: "Bind the service to 127.0.0.1 unless external access is intentionally required.",
            });
        }
        if (/debug\s*[:=]\s*true/i.test(content)) {
            const pattern = content.match(/debug\s*[:=]\s*true/i)?.[0] ?? "debug=true";
            issues.push({
                ruleId: "ai.debug-enabled",
                category: "ai-agent",
                severity: "medium",
                confidence: 0.78,
                title: "Agent debug mode appears enabled",
                why: "Debug modes often expose verbose logging or unsafe development behavior in production-like environments.",
                evidence: [{ label: "pattern", value: pattern }],
                locations: [{ file: rel, line: findLine(content, pattern) }],
                fixAvailability: "none",
                source: "static",
                remediation: "Disable debug mode outside local development to reduce verbose or unsafe runtime behavior.",
            });
        }
    }
    return issues;
}
export async function saveBaseline(rootDir, result) {
    const config = await loadCuratrixConfig(rootDir);
    const snapshot = {
        projectRoot: rootDir,
        createdAt: new Date().toISOString(),
        fingerprints: result.issues.map((issue) => issue.fingerprint).sort(),
    };
    const target = baselinePath(rootDir, config.baselineDir);
    await ensureDirectory(path.dirname(target));
    await writeText(target, JSON.stringify(snapshot, null, 2));
    return target;
}
export async function compareWithBaseline(rootDir, result) {
    const config = await loadCuratrixConfig(rootDir);
    const snapshot = await readJsonFile(baselinePath(rootDir, config.baselineDir));
    if (!snapshot) {
        return {
            ...result,
            artifacts: { ...result.artifacts, baselineDelta: { new: result.issues.length, resolved: 0, unchanged: 0 } },
            issues: result.issues.map((issue) => ({ ...issue, baselineStatus: "new" })),
        };
    }
    const baselineSet = new Set(snapshot.fingerprints);
    const currentSet = new Set(result.issues.map((issue) => issue.fingerprint));
    const baselineDelta = { new: 0, resolved: 0, unchanged: 0 };
    const issues = result.issues.map((issue) => {
        const baselineStatus = baselineSet.has(issue.fingerprint) ? "unchanged" : "new";
        baselineDelta[baselineStatus] += 1;
        return { ...issue, baselineStatus };
    });
    for (const fingerprint of baselineSet) {
        if (!currentSet.has(fingerprint)) {
            baselineDelta.resolved += 1;
        }
    }
    return { ...result, issues, artifacts: { ...result.artifacts, baselineDelta } };
}
export async function createFixPlan(rootDir, issueId, options) {
    const result = await scanProject({ rootDir, vulnerabilityProvider: options?.vulnerabilityProvider });
    const issue = result.issues.find((entry) => entry.id === issueId || entry.fingerprint === issueId);
    if (!issue) {
        throw new Error(`Issue ${issueId} was not found in a fresh scan.`);
    }
    if (issue.fixAvailability === "none") {
        return {
            issueId: issue.id,
            fixType: "unsupported",
            summary: "No safe automated fix is available for this issue.",
            patchPreview: "",
            riskLevel: "high",
            reversible: false,
            requiresReview: true,
            applySteps: ["Review the finding and remediate manually."],
        };
    }
    const location = issue.locations[0];
    const absolutePath = path.join(rootDir, location.file);
    const original = (await readTextIfExists(absolutePath)) ?? "";
    const updated = renderPatchedContent(issue.ruleId, original);
    const summary = fixSummary(issue.ruleId);
    return {
        issueId: issue.id,
        fixType: issue.ruleId,
        summary,
        patchPreview: createSimplePatch(location.file, original, updated),
        riskLevel: "low",
        reversible: true,
        requiresReview: true,
        applySteps: [`Review patch for ${location.file}.`, "Run with --apply to write the change."],
    };
}
export async function applyFix(options) {
    const plan = await createFixPlan(options.rootDir, options.issueId, { vulnerabilityProvider: options.vulnerabilityProvider });
    if (!options.apply) {
        return plan;
    }
    const result = await scanProject({ rootDir: options.rootDir, vulnerabilityProvider: options.vulnerabilityProvider });
    const issue = result.issues.find((entry) => entry.id === options.issueId || entry.fingerprint === options.issueId);
    if (!issue) {
        throw new Error(`Issue ${options.issueId} disappeared before apply.`);
    }
    const target = path.join(options.rootDir, issue.locations[0].file);
    const original = (await readTextIfExists(target)) ?? "";
    await fs.writeFile(target, renderPatchedContent(issue.ruleId, original), "utf8");
    return plan;
}
function baselinePath(rootDir, baseDir) {
    const key = createIssueId({
        ruleId: "baseline.project",
        category: "dependencies",
        severity: "low",
        confidence: 1,
        title: rootDir,
        why: rootDir,
        evidence: [],
        locations: [{ file: rootDir }],
        fixAvailability: "none",
        source: "static",
    }).fingerprint;
    return path.join(baseDir, `${key}.json`);
}
function applyConfigToIssues(issues, config) {
    return dedupeIssues(issues
        .filter((issue) => !config.ignoredRuleIds.includes(issue.ruleId))
        .map((issue) => ({
        ...issue,
        severity: config.severityOverrides[issue.ruleId] ?? issue.severity,
    })));
}
function applyConfigToAiIssues(issues, config) {
    return dedupeFinalIssues(issues
        .filter((issue) => !config.ignoredRuleIds.includes(issue.ruleId))
        .map((issue) => ({
        ...issue,
        severity: config.severityOverrides[issue.ruleId] ?? issue.severity,
    })));
}
function fixSummary(ruleId) {
    switch (ruleId) {
        case "secrets.env-not-ignored":
            return "Add .env to .gitignore.";
        case "infra.docker.missing-user":
            return "Append a non-root USER directive to the Dockerfile.";
        case "ai.open-bind-address":
            return "Change the bind address from 0.0.0.0 to 127.0.0.1.";
        case "ai.prompt-missing-delimiters":
            return "Wrap the prompt content with explicit <SYSTEM>/<USER> delimiters.";
        default:
            return "No safe automated fix is available.";
    }
}
function renderPatchedContent(ruleId, original) {
    switch (ruleId) {
        case "secrets.env-not-ignored":
            return original.trim().length === 0 ? ".env\n" : `${original.trimEnd()}\n.env\n`;
        case "infra.docker.missing-user":
            return `${original.trimEnd()}\n\nUSER node\n`;
        case "ai.open-bind-address":
            return original.replaceAll("0.0.0.0", "127.0.0.1");
        case "ai.prompt-missing-delimiters":
            return `<SYSTEM>\n${original.trim()}\n</SYSTEM>\n<USER>\n{{user_input}}\n</USER>\n`;
        default:
            return original;
    }
}
function redact(value) {
    if (value.length <= 8) {
        return "[redacted]";
    }
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
}
function shannonEntropy(value) {
    const counts = new Map();
    for (const char of value) {
        counts.set(char, (counts.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of counts.values()) {
        const probability = count / value.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}
function looksLikePath(value) {
    return value.includes("/") || value.includes("\\") || value.endsWith(".json") || value.endsWith(".ts");
}
function findLine(content, needle) {
    const index = content.indexOf(needle);
    if (index === -1) {
        return undefined;
    }
    return content.slice(0, index).split(/\r?\n/).length;
}
function dedupeIssues(issues) {
    const seen = new Set();
    return issues.filter((candidate) => {
        const key = JSON.stringify(candidate);
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}
function dedupeFinalIssues(issues) {
    const seen = new Set();
    return issues.filter((issue) => {
        const key = JSON.stringify(issue);
        if (seen.has(key)) {
            return false;
        }
        seen.add(key);
        return true;
    });
}
function finalizeIssue(candidate) {
    const identity = createIssueId(candidate);
    return { ...candidate, ...identity };
}
function downgradeSeverity(severity) {
    switch (severity) {
        case "critical":
            return "high";
        case "high":
            return "medium";
        case "medium":
            return "low";
        default:
            return "low";
    }
}
function createSimplePatch(file, before, after) {
    const beforeLines = before.split(/\r?\n/);
    const afterLines = after.split(/\r?\n/);
    return [
        `--- a/${file}`,
        `+++ b/${file}`,
        "@@",
        ...beforeLines.map((line) => `-${line}`),
        ...afterLines.map((line) => `+${line}`),
    ].join("\n");
}
function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
//# sourceMappingURL=scan.js.map