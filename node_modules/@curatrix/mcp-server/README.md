# Curatrix MCP Server

`@curatrix/mcp-server` exposes Curatrix scanning and fix workflows over MCP so AI agents can call them as tools over stdio.

## Tools

### `curatrix_scan`

Runs a Curatrix scan against the current project or a provided path.

Inputs:
- `path` (optional): project root to scan
- `format` (optional): `json` or `text`

Notes:
- Uses the static Curatrix scan path by default for speed and predictability
- Returns JSON text by default, including findings, summary, config state, and source metadata

### `curatrix_fix`

Applies Curatrix fixes for selected issues or all fixable issues in a project.

Inputs:
- `path` (optional): project root to fix
- `issueIds` (optional): list of issue ids or fingerprints to target
- `autoConfirm` (optional, default `true`): apply fixes without prompting

Behavior:
- Runs a fresh scan first
- Filters to requested issues when `issueIds` is provided
- Otherwise targets fixable issues only
- Returns a JSON summary of applied and skipped fixes

## Start the Server

From the workspace root:

```bash
npm run mcp:start
```

## Claude Desktop

Add Curatrix to your Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "curatrix": {
      "command": "npm",
      "args": ["run", "mcp:start"],
      "cwd": "C:\\Users\\rishi\\Curatrix"
    }
  }
}
```

## Cursor

Example MCP server entry for Cursor:

```json
{
  "mcpServers": {
    "curatrix": {
      "command": "npm",
      "args": ["run", "mcp:start"],
      "cwd": "C:\\Users\\rishi\\Curatrix"
    }
  }
}
```

## Development

Build the workspace:

```bash
npm run build
```

Smoke test the server:

```bash
$null | npm run mcp:start
```
