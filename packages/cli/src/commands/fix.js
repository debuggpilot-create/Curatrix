import path from "node:path";
import process from "node:process";
import { promises as fs } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { applyPatch, parsePatch } from "diff";
import { applyFix, createFixPlan } from "curatrix-core";
const execFileAsync = promisify(execFile);
export async function applyFixes({ rootDir, issues, autoConfirm, vulnerabilityProvider }) {
    const applied = [];
    const skipped = [];
    for (const issue of issues) {
        const shouldApply = autoConfirm || await promptForConfirmation(issue);
        if (!shouldApply) {
            skipped.push({ issueId: issue.id, reason: "User declined apply." });
            continue;
        }
        if (issue.patch) {
            const patchApplied = await applyUnifiedPatch(rootDir, issue);
            if (patchApplied) {
                applied.push({ issueId: issue.id, summary: issue.remediation ?? "Applied AI-generated patch." });
            }
            else {
                skipped.push({ issueId: issue.id, reason: "Patch could not be applied cleanly." });
            }
            continue;
        }
        const npmInstallCommand = extractNpmInstall(issue.remediation);
        if (npmInstallCommand) {
            await execFileAsync("npm", npmInstallCommand, { cwd: rootDir });
            applied.push({ issueId: issue.id, summary: `Ran npm ${npmInstallCommand.join(" ")}` });
            continue;
        }
        try {
            const plan = await createFixPlan(rootDir, issue.id, { vulnerabilityProvider });
            await backupIssueTargets(rootDir, issue);
            await applyFix({ rootDir, issueId: issue.id, apply: true, vulnerabilityProvider });
            applied.push({ issueId: issue.id, summary: plan.summary });
        }
        catch (error) {
            skipped.push({
                issueId: issue.id,
                reason: error instanceof Error ? error.message : String(error),
            });
        }
    }
    return { applied, skipped };
}
async function applyUnifiedPatch(rootDir, issue) {
    const patchText = issue.patch;
    if (!patchText) {
        return false;
    }
    const parsedPatches = parsePatch(patchText);
    for (const parsedPatch of parsedPatches) {
        const relativeTarget = parsedPatch.newFileName?.replace(/^b\//, "") ?? parsedPatch.oldFileName?.replace(/^a\//, "");
        if (!relativeTarget) {
            return false;
        }
        const absoluteTarget = path.join(rootDir, relativeTarget);
        const original = await fs.readFile(absoluteTarget, "utf8");
        await backupFile(absoluteTarget, original);
        const next = applyPatch(original, parsedPatch);
        if (typeof next !== "string") {
            return false;
        }
        await fs.writeFile(absoluteTarget, next, "utf8");
    }
    return true;
}
async function backupIssueTargets(rootDir, issue) {
    for (const location of issue.locations) {
        const absoluteTarget = path.join(rootDir, location.file);
        try {
            const original = await fs.readFile(absoluteTarget, "utf8");
            await backupFile(absoluteTarget, original);
        }
        catch {
            continue;
        }
    }
}
async function backupFile(target, contents) {
    const backupPath = `${target}.bak`;
    await fs.writeFile(backupPath, contents, "utf8");
}
async function promptForConfirmation(issue) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
        return false;
    }
    const { createInterface } = await import("node:readline/promises");
    const readline = createInterface({ input: process.stdin, output: process.stdout });
    try {
        const answer = await readline.question(`Apply fix for ${issue.id} (${issue.title})? [y/N] `);
        return /^y(es)?$/i.test(answer.trim());
    }
    finally {
        readline.close();
    }
}
function extractNpmInstall(remediation) {
    if (!remediation) {
        return undefined;
    }
    const match = remediation.match(/npm install\s+([^\n]+)/i);
    return match ? ["install", ...match[1].trim().split(/\s+/)] : undefined;
}
//# sourceMappingURL=fix.js.map
