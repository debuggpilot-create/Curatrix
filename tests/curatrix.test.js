import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scanProject, createFixPlan, applyFix, saveBaseline, compareWithBaseline } from "../packages/core/dist/index.js";
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, '..'); // Points to project root regardless of OS
const execFileAsync = promisify(execFile);


async function copyFixture(name) {
  const source = path.join(root, "fixtures", name);
  const target = await fs.mkdtemp(path.join(os.tmpdir(), `curatrix-${name}-`));
  await fs.cp(source, target, { recursive: true });
  return target;
}

test("scanProject reports dependency and infrastructure findings for risky fixture", async () => {
  const fixture = await copyFixture("node-risky");
  const result = await scanProject({ rootDir: fixture });

  const ruleIds = result.issues.map((issue) => issue.ruleId);
  assert.ok(ruleIds.includes("deps.weak-version-range"));
  assert.ok(ruleIds.includes("deps.risky-lifecycle-script"));
  assert.ok(ruleIds.includes("infra.docker.missing-user"));
  assert.ok(ruleIds.includes("infra.secret-logging"));
  assert.equal(result.summary.byCategory.dependencies > 0, true);
  assert.equal(result.summary.byCategory.infrastructure > 0, true);
});

test("scanProject reports agent-security findings for risky agent fixture", async () => {
  const fixture = await copyFixture("agent-risky");
  const result = await scanProject({ rootDir: fixture });

  const ruleIds = result.issues.map((issue) => issue.ruleId);
  assert.ok(ruleIds.includes("ai.prompt-missing-delimiters"));
  assert.ok(ruleIds.includes("ai.prompt-concatenation"));
  assert.ok(ruleIds.includes("ai.unsafe-exec"));
  assert.ok(ruleIds.includes("ai.open-bind-address"));
});

test("safe fixes preview and apply deterministic changes", async () => {
  const fixture = await copyFixture("agent-risky");
  const result = await scanProject({ rootDir: fixture });
  const issue = result.issues.find((entry) => entry.ruleId === "ai.open-bind-address");
  assert.ok(issue);

  const preview = await createFixPlan(fixture, issue.id);
  assert.match(preview.patchPreview, /127\.0\.0\.1/);

  await applyFix({ rootDir: fixture, issueId: issue.id, apply: true });
  const updated = await fs.readFile(path.join(fixture, "memory", "agent.js"), "utf8");
  assert.match(updated, /127\.0\.0\.1/);
  assert.doesNotMatch(updated, /0\.0\.0\.0/);
});

test("baseline save and compare classify unchanged and resolved issues", async () => {
  const fixture = await copyFixture("node-risky");
  const first = await scanProject({ rootDir: fixture });
  await saveBaseline(fixture, first);

  let compared = await compareWithBaseline(fixture, await scanProject({ rootDir: fixture }));
  assert.equal(compared.artifacts.baselineDelta?.unchanged, compared.issues.length);

  const dockerfile = path.join(fixture, "Dockerfile");
  const content = await fs.readFile(dockerfile, "utf8");
  await fs.writeFile(dockerfile, `${content.trimEnd()}\nUSER node\n`, "utf8");

  compared = await compareWithBaseline(fixture, await scanProject({ rootDir: fixture }));
  assert.equal((compared.artifacts.baselineDelta?.resolved ?? 0) > 0, true);
});

test("git history scan reports historical secret attribution", async () => {
  const fixture = await copyFixture("secrets-history");
  await execFileAsync("git", ["init"], { cwd: fixture });
  await execFileAsync("git", ["config", "user.name", "Curatrix Test"], { cwd: fixture });
  await execFileAsync("git", ["config", "user.email", "curatrix@example.com"], { cwd: fixture });
  await execFileAsync("git", ["add", "."], { cwd: fixture });
  await execFileAsync("git", ["commit", "-m", "add secret"], { cwd: fixture });
  await fs.writeFile(path.join(fixture, "app.js"), "console.log('sanitized');\n", "utf8");
  await execFileAsync("git", ["add", "app.js"], { cwd: fixture });
  await execFileAsync("git", ["commit", "-m", "remove secret"], { cwd: fixture });

  const result = await scanProject({ rootDir: fixture });
  const historyIssue = result.issues.find((issue) => issue.ruleId.startsWith("secrets.git-history."));
  assert.ok(historyIssue);
  assert.ok(historyIssue?.evidence.some((item) => item.label === "commit"));
  assert.ok(historyIssue?.evidence.some((item) => item.label === "author"));
});

test("clean fixture remains low noise", async () => {
  const fixture = await copyFixture("clean");
  const result = await scanProject({ rootDir: fixture });
  assert.equal(result.issues.length, 0);
});

test("project config toggles modules, overrides severities, suppresses rules, and customizes baseline storage", async () => {
  const fixture = await copyFixture("agent-risky");
  const customBaselineDir = path.join(fixture, ".curatrix-baselines");

  await fs.writeFile(
    path.join(fixture, ".curatrixrc.json"),
    JSON.stringify({
      modules: { aiAgent: false },
      severityOverrides: { "secrets.env-not-ignored": "critical" },
      baselineDir: customBaselineDir,
    }, null, 2),
    "utf8",
  );

  await fs.writeFile(path.join(fixture, ".env"), "API_KEY=demo\n", "utf8");
  await fs.writeFile(path.join(fixture, ".gitignore"), "", "utf8");
  await fs.writeFile(path.join(fixture, ".curatrixignore.json"), JSON.stringify(["secrets.high-entropy"], null, 2), "utf8");
  await fs.writeFile(path.join(fixture, "notes.txt"), "abcdefghijklmnopqrstuvwxyz1234567890\n", "utf8");

  const result = await scanProject({ rootDir: fixture });
  assert.equal(result.issues.some((issue) => issue.category === "ai-agent"), false);

  const envIssue = result.issues.find((issue) => issue.ruleId === "secrets.env-not-ignored");
  assert.equal(envIssue?.severity, "critical");
  assert.equal(result.issues.some((issue) => issue.ruleId === "secrets.high-entropy"), false);

  await saveBaseline(fixture, result);
  const baselineFiles = await fs.readdir(customBaselineDir);
  assert.equal(baselineFiles.length > 0, true);
});

test("scanProject exposes config state and filters ignored rules from results", async () => {
  const fixture = await copyFixture("node-risky");

  await fs.writeFile(
    path.join(fixture, ".curatrixrc.json"),
    JSON.stringify({
      modules: {
        aiAgent: false,
      },
      severityOverrides: {
        "deps.missing-lockfile": "critical",
      },
    }, null, 2),
    "utf8",
  );

  await fs.writeFile(
    path.join(fixture, ".curatrixignore.json"),
    JSON.stringify(["infra.docker.latest-tag"], null, 2),
    "utf8",
  );

  const result = await scanProject({ rootDir: fixture });

  assert.ok(result.config);
  assert.deepEqual(result.config?.modules, {
    deps: true,
    secrets: true,
    infra: true,
    aiAgent: false,
  });
  assert.deepEqual(result.config?.ignoredRules, ["infra.docker.latest-tag"]);
  assert.deepEqual(result.config?.severityOverrides, {
    "deps.missing-lockfile": "critical",
  });

  assert.equal(result.issues.some((issue) => issue.ruleId === "infra.docker.latest-tag"), false);

  const overriddenIssue = result.issues.find((issue) => issue.ruleId === "deps.missing-lockfile");
  assert.equal(overriddenIssue?.severity, "critical");
});

test("dependency scan reports suspicious install scripts, transitive depth, and honors VEX suppression", async () => {
  const fixture = await fs.mkdtemp(path.join(os.tmpdir(), "curatrix-supply-chain-"));

  await fs.writeFile(
    path.join(fixture, "package.json"),
    JSON.stringify({
      name: "supply-chain-risk",
      version: "1.0.0",
      scripts: {
        postinstall: "node -e \"eval(Buffer.from('6869','hex').toString())\"",
      },
      dependencies: {
        directpkg: "1.2.3",
      },
    }, null, 2),
    "utf8",
  );

  await fs.writeFile(
    path.join(fixture, "package-lock.json"),
    JSON.stringify({
      name: "supply-chain-risk",
      lockfileVersion: 2,
      packages: {
        "": {
          dependencies: {
            directpkg: "1.2.3",
          },
        },
        "node_modules/directpkg": {
          version: "1.2.3",
          dependencies: {
            transitivepkg: "0.0.5",
          },
        },
        "node_modules/directpkg/node_modules/transitivepkg": {
          version: "0.0.5",
        },
      },
    }, null, 2),
    "utf8",
  );

  await fs.writeFile(
    path.join(fixture, ".curatrix.vex.json"),
    JSON.stringify({
      product_tree: {
        full_product_names: [
          { product_id: "pkg:directpkg@1.2.3", name: "directpkg@1.2.3" },
        ],
      },
      vulnerabilities: [
        {
          cve: "CVE-2024-1111",
          product_status: {
            not_affected: ["pkg:directpkg@1.2.3"],
          },
        },
      ],
    }, null, 2),
    "utf8",
  );

  const mockProvider = {
    name: "mock-osv",
    async getVulnerabilities() {
      return [];
    },
    async getPackageVersionVulnerabilities() {
      return [
        {
          packageName: "directpkg",
          packageVersion: "1.2.3",
          severity: "high",
          advisory: "CVE-2024-1111 | direct advisory",
          aliases: ["CVE-2024-1111"],
        },
        {
          packageName: "transitivepkg",
          packageVersion: "0.0.5",
          severity: "high",
          advisory: "CVE-2024-2222 | transitive advisory",
          aliases: ["CVE-2024-2222"],
        },
      ];
    },
  };

  const result = await scanProject({ rootDir: fixture, vulnerabilityProvider: mockProvider });

  assert.ok(result.issues.some((issue) => issue.ruleId === "deps.suspicious-install-script"));
  assert.equal(result.issues.some((issue) => issue.ruleId === "deps.provider-vulnerability"), false);

  const transitive = result.issues.find((issue) => issue.ruleId === "deps.transitive-cve");
  assert.ok(transitive);
  assert.equal(transitive?.depth, 2);
  assert.equal(transitive?.vexStatus, undefined);
});
