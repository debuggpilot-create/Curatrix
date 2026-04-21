# Curatrix MCP Server

`curatrix-mcp-server` exposes Curatrix scans and fixes as MCP tools over stdio.

## Features

- `curatrix_scan`: scan a project with Curatrix and return structured findings
- `curatrix_fix`: apply available Curatrix fixes and return a detailed summary
- OSV-backed vulnerability provider enabled during MCP scans
- Human-readable correction context for AI agents

## Installation

From the workspace root:

```bash
npm install
npm run build
```

Run the server locally:

```bash
npm run mcp:start
```

Or from this package directly:

```bash
npm --workspace curatrix-mcp-server run start
```

## Tool Reference

### `curatrix_scan`

Inputs:

- `path` optional project root, defaults to the current working directory
- `format` optional `json` or `text`, defaults to `json`

Returns:

- project metadata
- scan summary
- issue list with `correctionContext`

### `curatrix_fix`

Inputs:

- `path` optional project root, defaults to the current working directory
- `issueIds` optional list of issue ids or fingerprints
- `autoConfirm` optional boolean, defaults to `true`

Returns:

- `fixedCount`
- selected issues with correction context
- `changes`
- `skipped`

## Claude Desktop / Cursor Example

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
