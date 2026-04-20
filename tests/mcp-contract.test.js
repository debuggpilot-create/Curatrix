import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runCuratrixFixTool, runCuratrixScanTool } from "../packages/mcp-server/dist/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const root = join(__dirname, "..");

async function copyFixture(name) {
  const source = path.join(root, "fixtures", name);
  const target = await fs.mkdtemp(path.join(os.tmpdir(), `curatrix-mcp-${name}-`));
  await fs.cp(source, target, { recursive: true });
  return target;
}

function parseToolPayload(response) {
  assert.equal(response?.isError, undefined);
  assert.ok(Array.isArray(response?.content));
  assert.equal(response.content[0]?.type, "text");
  return JSON.parse(response.content[0].text);
}

test("curatrix_scan includes correctionContext for every returned issue", async () => {
  const fixture = await copyFixture("node-risky");
  const response = await runCuratrixScanTool({ path: fixture, format: "json" });
  const payload = parseToolPayload(response);

  assert.ok(Array.isArray(payload.issues));
  assert.ok(payload.issues.length > 0);

  for (const issue of payload.issues) {
    assert.ok(issue.correctionContext);
    assert.equal(typeof issue.correctionContext.type, "string");
    assert.equal(typeof issue.correctionContext.action, "string");
    assert.equal(typeof issue.correctionContext.reasoning, "string");
    assert.ok(issue.correctionContext.reasoning.trim().length > 0);
    assert.equal(typeof issue.correctionContext.confidence, "number");
    assert.ok(issue.correctionContext.confidence >= 0.5);
    assert.ok(issue.correctionContext.confidence <= 0.99);
  }
});

test("curatrix_fix returns fixedCount, changes, skipped, and human-readable reasoning", async () => {
  const fixture = await copyFixture("agent-risky");
  const response = await runCuratrixFixTool({ path: fixture, autoConfirm: true });
  const payload = parseToolPayload(response);

  assert.equal(typeof payload.fixedCount, "number");
  assert.ok(Array.isArray(payload.changes));
  assert.ok(Array.isArray(payload.skipped));
  assert.ok(payload.fixedCount >= 1);
  assert.ok(payload.changes.length >= 1);

  for (const change of payload.changes) {
    assert.equal(typeof change.file, "string");
    assert.ok(change.file.length > 0);
    assert.equal(typeof change.changeType, "string");
    assert.ok(["dependency-update", "config-patch", "code-patch"].includes(change.changeType));
    assert.equal(typeof change.reasoning, "string");
    assert.ok(change.reasoning.trim().length > 0);
  }
});
