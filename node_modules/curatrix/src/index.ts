#!/usr/bin/env node
import process from "node:process";
import { readFileSync } from "node:fs";
import { Command, Help, Option, type CommanderError } from "commander/esm.mjs";
import { applyFix, compareWithBaseline, createFixPlan, saveBaseline, scanProject, type ScanResult, type Severity } from "@curatrix/core";
import { OsvVulnerabilityProvider } from "@curatrix/adapters";

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
      "curatrix scan fixtures/node-risky --format json",
      "curatrix fix fixtures/agent-risky --issue <id> --dry-run",
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
    .addOption(new Option("--format <format>", "Output format").choices(["text", "json"]).default("text"))
    .addOption(new Option("--baseline <mode>", "Baseline action to perform").choices(["set", "compare"]))
    .option("--ci", "Exit non-zero on high or critical findings")
    .action(async (rootDir: string, options: { format: "text" | "json"; baseline?: "set" | "compare"; ci?: boolean }) => {
      let result = await scanProject({ rootDir, ci: options.ci ?? false, vulnerabilityProvider: osvProvider });
      if (options.baseline === "compare") {
        result = await compareWithBaseline(rootDir, result);
      }

      if (options.baseline === "set") {
        const baselinePath = await saveBaseline(rootDir, result);
        if (options.format === "json") {
          process.stdout.write(`${JSON.stringify({ baselinePath, result }, null, 2)}\n`);
        } else {
          process.stdout.write(renderText(result));
          process.stdout.write(`\nBaseline saved to ${baselinePath}\n`);
        }
      } else {
        outputResult(result, options.format);
      }

      process.exitCode = shouldFailCi(result, options.ci ?? false) ? 1 : 0;
    });

  setHelpMetadata(scanCommand, {
    examples: [
      "curatrix scan .",
      "curatrix scan ./repo --baseline compare",
      "curatrix scan ./repo --format json --ci",
    ],
    exitCodes: [
      "0  Scan completed and no CI threshold was breached.",
      "1  High or critical findings were detected with --ci, or the command failed.",
    ],
  });

  const fixCommand = program
    .command("fix")
    .description("Preview or apply a safe automated fix for a specific issue.")
    .argument("[path]", "Project path containing the issue", process.cwd())
    .requiredOption("--issue <id>", "Issue id or fingerprint to fix")
    .addOption(new Option("--format <format>", "Output format").choices(["text", "json"]).default("text"))
    .option("--apply", "Apply the generated fix")
    .option("--dry-run", "Preview the generated fix without writing files")
    .action(async (rootDir: string, options: { issue: string; format: "text" | "json"; apply?: boolean }) => {
      const plan = options.apply
        ? await applyFix({ rootDir, issueId: options.issue, apply: true, vulnerabilityProvider: osvProvider })
        : await createFixPlan(rootDir, options.issue, { vulnerabilityProvider: osvProvider });

      if (options.format === "json") {
        process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
      } else {
        process.stdout.write(`Fix: ${plan.summary}\n`);
        process.stdout.write(`Risk: ${plan.riskLevel} | Reversible: ${String(plan.reversible)} | Requires review: ${String(plan.requiresReview)}\n\n`);
        process.stdout.write(`${plan.patchPreview}\n`);
      }
    });

  setHelpMetadata(fixCommand, {
    examples: [
      "curatrix fix . --issue abc123 --dry-run",
      "curatrix fix ./repo --issue abc123 --apply",
      "curatrix fix ./repo --issue abc123 --format json",
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

function outputResult(result: ScanResult, format: "text" | "json"): void {
  if (format === "json") {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  process.stdout.write(renderText(result));
}

function renderText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`Curatrix scan for ${result.project.name}`);
  lines.push(`Issues: ${result.summary.totalIssues}`);
  lines.push(`Severity counts: critical=${result.summary.bySeverity.critical}, high=${result.summary.bySeverity.high}, medium=${result.summary.bySeverity.medium}, low=${result.summary.bySeverity.low}`);
  if (result.artifacts.baselineDelta) {
    lines.push(`Baseline delta: new=${result.artifacts.baselineDelta.new}, resolved=${result.artifacts.baselineDelta.resolved}, unchanged=${result.artifacts.baselineDelta.unchanged}`);
  }
  lines.push("");
  for (const issue of result.issues) {
    const location = issue.locations[0];
    lines.push(`[${issue.severity.toUpperCase()}] ${issue.title}`);
    lines.push(`  id: ${issue.id}`);
    lines.push(`  rule: ${issue.ruleId}`);
    lines.push(`  file: ${location?.file ?? "<unknown>"}${location?.line ? `:${location.line}` : ""}`);
    lines.push(`  why: ${issue.why}`);
    if (issue.baselineStatus) {
      lines.push(`  baseline: ${issue.baselineStatus}`);
    }
    for (const evidence of issue.evidence) {
      lines.push(`  evidence: ${evidence.label}=${evidence.value}`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
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
