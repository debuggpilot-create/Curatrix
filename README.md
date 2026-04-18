# Curatrix ???

Universal project health & security curator. Local-first. Deterministic. AI-ready.

Curatrix helps you audit repositories for security, supply-chain risk, infrastructure mistakes, secrets exposure, and AI-agent hygiene without sending your code to a third-party service by default. It is designed for fast local scans, stable machine-readable output, and safe, review-first remediation.

## Why Curatrix

- Local-first: scans run on your machine by default
- Deterministic: rules produce explainable findings with evidence
- Review-first: automated fixes are previewable before apply
- CI-friendly: non-zero exits when configured thresholds are breached
- AI-ready: agent-specific checks ship today, deeper AI analysis can be layered later
- Extensible: adapters, config files, and stable JSON output are built in from the start

## Installation

```bash
npm install -g curatrix
# or
npx curatrix scan
```

## Quick Start

Run a scan in the current project:

```bash
curatrix scan .
```

Generate JSON output for scripts or CI:

```bash
curatrix scan . --format json
```

Save and compare a local baseline:

```bash
curatrix scan . --baseline set
curatrix scan . --baseline compare
```

Preview a safe automated fix:

```bash
curatrix fix . --issue <issue-id> --dry-run
```

Apply a safe automated fix:

```bash
curatrix fix . --issue <issue-id> --apply
```

Show CLI help:

```bash
curatrix --help
curatrix scan --help
curatrix fix --help
```

## What Curatrix Checks in v0.1.0

### Dependency and Supply Chain
- Weak or floating version ranges in `package.json`
- Risky lifecycle scripts like `preinstall`, `install`, `postinstall`, and `prepare`
- Missing Node lockfiles
- Optional OSV-backed vulnerability lookups with local caching
- Basic usage-aware severity reduction for declared-but-unused dependencies

### Secrets and Git Hygiene
- Known secret patterns such as AWS keys, Stripe keys, JWTs, and private keys
- High-entropy secret candidates
- `.env` files that are present but not ignored
- Historical secret attribution from git history when a repository is available

### Infrastructure and CI
- Docker images pinned to `:latest`
- Dockerfiles missing a non-root `USER`
- `COPY . .` before build steps
- Privileged containers in infrastructure config
- Secrets printed in workflow logs
- Missing visible test steps in GitHub Actions workflows

### AI-Agent Security
- Missing `<SYSTEM>` / `<USER>` prompt delimiters
- Direct prompt concatenation with user-controlled input
- Unsafe execution primitives such as `eval()` and `exec()`
- Agent services bound to `0.0.0.0`
- Debug mode left enabled

## Output Model

Curatrix produces both readable terminal output and stable JSON output.

Each finding includes:
- `ruleId`
- severity
- explanation (`why`)
- evidence
- file and line location when available
- fix availability

JSON scan results also include top-level config state for the run, including enabled modules, ignored rules, and severity overrides.

## Safe Fixes

Curatrix only automates narrow, deterministic fixes in v0.1.0.

Supported fixes include:
- add `.env` to `.gitignore`
- append `USER node` to a Dockerfile
- replace `0.0.0.0` with `127.0.0.1`
- wrap prompt content with `<SYSTEM>` / `<USER>` delimiters

Recommended workflow:

```bash
curatrix fix . --issue <issue-id> --dry-run
curatrix fix . --issue <issue-id> --apply
```

## Configuration

Curatrix supports layered configuration:
- project config: `.curatrixrc.json`
- global config: `~/.curatrix/config.json`
- ignored rules: `.curatrixignore.json`

### Example `.curatrixrc.json`

```json
{
  "modules": {
    "aiAgent": false,
    "secrets": true,
    "infrastructure": true,
    "dependencies": true
  },
  "severityOverrides": {
    "deps.missing-lockfile": "high"
  },
  "baselineDir": "./.curatrix-baselines"
}
```

### Example `.curatrixignore.json`

```json
[
  "infra.docker.latest-tag",
  "secrets.high-entropy"
]
```

### Supported Config Keys

- `modules`: enable or disable major scan modules
- `severityOverrides`: override severity by `ruleId`
- `baselineDir`: customize where baseline snapshots are stored
- `.curatrixignore.json`: suppress findings by `ruleId`

If config files are missing or malformed, Curatrix falls back to safe defaults.

## Caching and Network Behavior

Curatrix is local-first by default.

When vulnerability lookups are enabled through the OSV adapter:
- requests are rate-limited
- responses are cached under `~/.curatrix/cache/osv/`
- cache TTL is 24 hours
- network failures fall back gracefully to empty vulnerability results

Curatrix does not require network access for its core deterministic scans.

## Exit Codes

- `0`: successful execution with no configured CI threshold breach
- `1`: invalid arguments, runtime failure, or CI threshold failure

With `--ci`, Curatrix exits non-zero when high or critical findings are present.

## CLI Reference

### `curatrix scan`

```bash
curatrix scan [path] [--format text|json] [--baseline set|compare] [--ci]
```

### `curatrix fix`

```bash
curatrix fix [path] --issue <id> [--dry-run|--apply] [--format text|json]
```

### `curatrix --version`

```bash
curatrix --version
```

## Development

Install dependencies:

```bash
npm install
```

Build the workspace:

```bash
npm run build
```

Run tests:

```bash
npm test
```

Link the CLI globally for local development:

```bash
npm run link
curatrix scan --help
```

Dry-run the published package contents:

```bash
npm run pack:dry
```

## Workspace Layout

- `packages/core`: scan engine, rules, fix pipeline, baselines, config loading
- `packages/adapters`: OSV provider and reserved extension seams
- `packages/cli`: Commander-based CLI and structured help output
- `fixtures/`: local test fixtures
- `tests/`: integration and contract tests

## Current Scope

Curatrix v0.1.0 is intentionally focused on a trustworthy MVP:
- deterministic local scanning
- stable JSON output
- baseline save/compare
- a small set of safe automated fixes
- adapter and config seams for future expansion

The following are intentionally deferred beyond v0.1.0:
- MCP transport
- SBOM generation
- malware scanning
- remote control modes
- richer ecosystem coverage beyond the initial Node-first path
- deeper AI-assisted analysis

## License

MIT
