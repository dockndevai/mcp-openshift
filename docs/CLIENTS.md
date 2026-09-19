# Installing `mcp-openshift` in your MCP client

`mcp-openshift` is a **stdio** MCP server. Any MCP-compatible agent can run it.

- **From npm (recommended):** `npx -y @dockndevai/mcp-openshift`
- **From source:** `node /ABSOLUTE/PATH/TO/mcp-openshift/dist/index.js` after `npm install && npm run build`.

> You need `OPENSHIFT_SERVER` and a credential. Quickest: in the OpenShift web console, **username
> menu → Copy login command → Display Token**, then set `OPENSHIFT_SERVER` + `OPENSHIFT_TOKEN`.
> **Start in `read-only` mode.** See [`.env.example`](../.env.example) for every variable.

## Claude Code (CLI)

```bash
claude mcp add openshift \
  -e OPENSHIFT_SERVER="https://api.cluster.example.com:6443" \
  -e OPENSHIFT_TOKEN="sha256~..." \
  -e OPENSHIFT_MODE="read-only" \
  -- npx -y @dockndevai/mcp-openshift
```

Use `-e OPENSHIFT_USERNAME=... -e OPENSHIFT_PASSWORD=...` instead of the token for username/password
auth. Add `-e OPENSHIFT_CA_CERT=/path/ca.crt` for a private-CA cluster. List with `claude mcp list`,
remove with `claude mcp remove openshift`.

## Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openshift": {
      "command": "npx",
      "args": ["-y", "@dockndevai/mcp-openshift"],
      "env": {
        "OPENSHIFT_SERVER": "https://api.cluster.example.com:6443",
        "OPENSHIFT_TOKEN": "sha256~...",
        "OPENSHIFT_MODE": "read-only"
      }
    }
  }
}
```

## Cursor

`.cursor/mcp.json` (or `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "openshift": {
      "command": "npx",
      "args": ["-y", "@dockndevai/mcp-openshift"],
      "env": { "OPENSHIFT_SERVER": "https://api.cluster.example.com:6443", "OPENSHIFT_TOKEN": "sha256~...", "OPENSHIFT_MODE": "read-only" }
    }
  }
}
```

## OpenAI Codex CLI

`~/.codex/config.toml`:

```toml
[mcp_servers.openshift]
command = "npx"
args = ["-y", "@dockndevai/mcp-openshift"]
env = { OPENSHIFT_SERVER = "https://api.cluster.example.com:6443", OPENSHIFT_TOKEN = "sha256~...", OPENSHIFT_MODE = "read-only" }
```

## VS Code (Copilot / Agent mode)

`.vscode/mcp.json` (top-level key is `servers`):

```json
{
  "servers": {
    "openshift": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@dockndevai/mcp-openshift"],
      "env": { "OPENSHIFT_SERVER": "https://api.cluster.example.com:6443", "OPENSHIFT_TOKEN": "sha256~...", "OPENSHIFT_MODE": "read-only" }
    }
  }
}
```

## Windsurf

`~/.codeium/windsurf/mcp_config.json` with the same `mcpServers` block as Cursor, then **Refresh**.

## Verify

On startup the server logs to **stderr**:

```
openshift-mcp connected [server=https://api…:6443, auth=token, mode=read-only, tools=6: whoami, list_projects, …]
```

Ask your agent to *"list my OpenShift projects"* to confirm.
