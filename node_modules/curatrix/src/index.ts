#!/usr/bin/env node
import process from "node:process";
import { readFileSync } from "node:fs";
import { Command, Help, Option, type CommanderError } from "commander/esm.mjs";
import { applyFixes, compareWithBaseline, createFixPlan, saveBaseline, scanProject, type Issue, type ScanResult, type Severity } from "@curatrix/core";
import { OsvVulnerabilityProvider } from "@curatrix/adapters";
import { outputResult, renderFixPreview, renderFixResult, renderText } from "./output.js";

const CLI_PACKAGE = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const osvProvider = new OsvVulnerabilityProvider();

interface HelpMetadata {
  examples: string[];
  exitCodes: string[];
}

const helpMetadata = new WeakMap<Command, HelpMetadata>();

class StructuredHelp extends Help {
  public formatHelp(command: Command, helper: Help): string {
    const lines: string[] = [];
    const description = command.description();
    const metadata = helpMetadata.get(command);

    lines.push(command.parent ? command.name() : `${command.name()} v${CLI_PACKAGE.version}`);

    if (description) {
      lines.push("");
      lines.push(description);
    }

    lines.push("");
    lines.push("Usage");
    lines.push(`  ${helper.commandUsage(command)}`);

    const subcommands = helper.visibleCommands(command);
    if (subcommands.length > 0) {
      lines.push("");
      lines.push("Commands");
      for (const subcommand of subcommands) {
        lines.push(`  ${helper.subcommandTerm(subcommand).padEnd(24)} ${subcommand.description()}`);
      }
    }

    const options = helper.visibleOptions(command);
    if (options.length > 0) {
      lines.push("");
      lines.push("Options");
      const width = Math.max(...options.map((option: Option) => helper.optionTerm(option).length));
      for (const option of options) {
        lines.push(`  ${helper.optionTerm(option).padEnd(width)}  ${helper.optionDescription(option)}`);
      }
    }

    if (metadata?.examples.length) {
      lines.push("");
      lines.push("Examples");
      for (const example of metadata.examples) {
        lines.push(`  ${example}`);
      }
    }

    if (metadata?.exitCodes.length) {
      lines.push("");
      lines.push("Exit Codes");
      for (const exitCode of metadata.exitCodes) {
        lines.push(`  ${exitCode}`);
      }
    }

    return `${lines.join("\n")}\n`;
  }
}

async function main(): Promise<void> {
  const program = createProgram();
  await program.parseAsync(process.argv);
}

function createProgram(): Command {
  const program = new Command();

  program
    .name("curatrix")
    .description("Local-first project auditing with deterministic scans and review-first fixes.")
    .version(CLI_PACKAGE.version, "--version", "Show the CLI version")
    .configureHelp({
      helpWidth: 100,
      formatHelp: (command: Command, helper: Help) => new StructuredHelp().formatHelp(command, helper),
    })
    .showHelpAfterError("\nRun `curatrix --help` for usage.")
    .allowExcessArguments(false);

  setHelpMetadata(program, {
    examples: [
      "curatrix scan .",
      "curatrix scan fixtures/node-risky --format json --enable-ai-audit",
      "curatrix fix . --issue <id> --apply",
    ],
    exitCodes: [
      "0  Command completed successfully.",
      "1  Invalid arguments, command errors, or CI threshold failure.",
    ],
  });

  const scanCommand = program
    .command("scan")
    .description("Run a deterministic local project audit.")
    .argument("[path]", "Project path to scan", process.cwd())
    .addOption(new Option("--format <format>", "Output format").choices(["text", "json", "markdown"]).default("text"))
    .addOption(new Option("--baseline <mode>", "Baseline action to perform").choices(["set", "compare"]))
    .option("--ci", "Exit non-zero on high or critical findings")
    .option("--enable-ai-audit", "Run AI-assisted semantic auditing using the OpenAI API")
    .option("--ai-key <key>", "OpenAI API key for AI-assisted audit")
    .action(async (rootDir: string, options: { format: "text" | "json" | "markdown"; baseline?: "set" | "compare"; ci?: boolean; enableAiAudit?: boolean; aiKey?: string }) => {
      const aiApiKey = options.enableAiAudit ? await resolveAiKey(options.aiKey) : undefined;
      let result = await scanProject({
        rootDir,
        ci: options.ci ?? false,
        vulnerabilityProvider: osvProvider,
        enableAiAudit: options.enableAiAudit ?? false,
        aiApiKey,
      });

      if (options.baseline === "compare") {
        result = await compareWithBaseline(rootDir, result);
      }

      if (options.baseline === "set") {
        const baselinePath = await saveBaseline(rootDir, result);
        if (options.format === "json") {
          process.stdout.write(`${JSON.stringify({ baselinePath, result }, null, 2)}\n`);
        } else {
          process.stdout.write(outputResult(result, options.format));
          process.stdout.write(`\nBaseline saved to ${baselinePath}\n`);
        }
      } else {
        process.stdout.write(outputResult(result, options.format));
      }

      process.exitCode = shouldFailCi(result, options.ci ?? false) ? 1 : 0;
    });

  setHelpMetadata(scanCommand, {
    examples: [
      "curatrix scan .",
      "curatrix scan ./repo --enable-ai-audit",
      "curatrix scan ./repo --format json --ci",
      "curatrix scan ./repo --format markdown",
    ],
    exitCodes: [
      "0  Scan completed and no CI threshold was breached.",
      "1  High or critical findings were detected with --ci, or the command failed.",
    ],
  });

  const fixCommand = program
    .command("fix")
    .description("Preview or apply fixes for a specific issue.")
    .argument("[path]", "Project path containing the issue", process.cwd())
    .requiredOption("--issue <id>", "Issue id or fingerprint to fix")
    .addOption(new Option("--format <format>", "Output format").choices(["text", "json"]).default("text"))
    .option("--apply", "Apply the generated fix")
    .option("--dry-run", "Preview the generated fix without writing files")
    .option("--enable-ai-audit", "Include AI findings when locating the target issue")
    .option("--ai-key <key>", "OpenAI API key for AI-assisted audit")
    .action(async (rootDir: string, options: { issue: string; format: "text" | "json"; apply?: boolean; enableAiAudit?: boolean; aiKey?: string }) => {
      const aiApiKey = options.enableAiAudit ? await resolveAiKey(options.aiKey) : undefined;
      const result = await scanProject({
        rootDir,
        vulnerabilityProvider: osvProvider,
        enableAiAudit: options.enableAiAudit ?? false,
        aiApiKey,
      });
      const issue = result.issues.find((entry) => entry.id === options.issue || entry.fingerprint === options.issue);
      if (!issue) {
        throw new Error(`Issue ${options.issue} was not found in a fresh scan.`);
      }

      if (!options.apply) {
        const preview = issue.patch
          ? {
              issueId: issue.id,
              fixType: issue.ruleId,
              summary: issue.remediation ?? "AI audit generated a candidate patch.",
              patchPreview: issue.patch,
              riskLevel: "medium",
              reversible: true,
              requiresReview: true,
              applySteps: ["Review the patch carefully before applying it."],
            }
          : await createFixPlan(rootDir, issue.id, { vulnerabilityProvider: osvProvider });

        if (options.format === "json") {
          process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
        } else {
          process.stdout.write(renderFixPreview(issue, preview.patchPreview));
        }
        return;
      }

      const applyResult = await applyFixes({
        rootDir,
        issues: [issue],
        autoConfirm: true,
        vulnerabilityProvider: osvProvider,
      });

      if (options.format === "json") {
        process.stdout.write(`${JSON.stringify(applyResult, null, 2)}\n`);
      } else {
        process.stdout.write(renderFixResult(issue, applyResult));
      }
    });

  setHelpMetadata(fixCommand, {
    examples: [
      "curatrix fix . --issue abc123 --dry-run",
      "curatrix fix ./repo --issue abc123 --apply",
      "curatrix fix ./repo --issue abc123 --enable-ai-audit",
    ],
    exitCodes: [
      "0  Fix preview or apply completed successfully.",
      "1  The issue was not found, arguments were invalid, or apply failed.",
    ],
  });

  return program;
}

function setHelpMetadata(command: Command, metadata: HelpMetadata): void {
  helpMetadata.set(command, metadata);
  command.configureHelp({
    helpWidth: 100,
    formatHelp: (target: Command, helper: Help) => new StructuredHelp().formatHelp(target, helper),
  });
}

async function resolveAiKey(cliKey: string | undefined): Promise<string> {
  const providedKey = cliKey ?? process.env.OPENAI_API_KEY;
  if (providedKey) {
    return providedKey;
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("AI audit is enabled but no OpenAI API key was provided. Use --ai-key or OPENAI_API_KEY.");
  }

  const { createInterface } = await import("node:readline/promises");
  const readline = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await readline.question("Enter OpenAI API key: ");
    if (!answer.trim()) {
      throw new Error("AI audit requires an OpenAI API key.");
    }
    return answer.trim();
  } finally {
    readline.close();
  }
}

function shouldFailCi(result: ScanResult, ci: boolean): boolean {
  if (!ci) {
    return false;
  }
  return result.issues.some((issue) => failAtSeverity(issue.severity, "high"));
}

function failAtSeverity(current: Severity, threshold: Severity): boolean {
  const ranking: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
  return ranking[current] >= ranking[threshold];
}

main().catch((error: unknown) => {
  const commanderError = error as Partial<CommanderError>;
  if (commanderError.code === "commander.helpDisplayed") {
    return;
  }
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
