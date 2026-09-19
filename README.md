# mcp-openshift

[![npm](https://img.shields.io/npm/v/@dockndevai/mcp-openshift)](https://www.npmjs.com/package/@dockndevai/mcp-openshift)
[![CI](https://github.com/dockndevai/mcp-openshift/actions/workflows/ci.yml/badge.svg)](https://github.com/dockndevai/mcp-openshift/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A **safe-by-default** [Model Context Protocol](https://modelcontextprotocol.io) server for **OpenShift / Kubernetes**. It lets an agent explore and operate a cluster — projects, pods and logs, deployments and deploymentconfigs, routes, services, builds, imagestreams, and any resource by kind — and, in higher modes, scale workloads, restart deployments, apply manifests, and delete.

Connect with a **token from the web console** you already use, or your **username/password** against the cluster's local identity provider.

Part of the [dockndevai MCP server suite](https://dockndevai.github.io/) — one governance model across all of them.

## What it gives an agent

Starts **read-only** (see [Safe by default](#safe-by-default)); higher-capability tools are only registered when you raise the mode.

| Tool | For | Needs mode |
|---|---|---|
| `whoami` | confirm the authenticated identity | read-only |
| `list_projects` | projects/namespaces you can see | read-only |
| `list_resources` | list any kind (± namespace, label selector) | read-only |
| `get_resource` | one resource with full spec/status | read-only |
| `pod_logs` | a pod's container logs | read-only |
| `list_events` | recent events in a namespace | read-only |
| `scale` | set replicas on a Deployment/DeploymentConfig | read-write |
| `rollout_restart` | restart a Deployment | read-write |
| `apply_resource` | create/update from a manifest (SSA) | read-write + `OPENSHIFT_ALLOW_APPLY` |
| `delete_resource` | delete a resource | admin + `OPENSHIFT_ALLOW_DELETE` |

## Install

```bash
npx -y @dockndevai/mcp-openshift
```

You need your cluster's **API URL** and a credential. The quickest, since you use the browser console:

> In the OpenShift web console, click your **username (top-right) → Copy login command → Display Token**. Copy the value after `--token=` (`sha256~…`) and the URL after `--server=`.

Then set `OPENSHIFT_SERVER` + `OPENSHIFT_TOKEN`. (Console tokens are short-lived; grab a fresh one when it expires, or use username/password below, which re-logs in automatically.)

## Configure

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

See [docs/CLIENTS.md](docs/CLIENTS.md) for Claude Code / Cursor / Codex / VS Code / Windsurf, and [.env.example](.env.example) for every variable.

## Authentication

Auth mode is chosen automatically (override with `OPENSHIFT_AUTH`):

- **token** — `OPENSHIFT_TOKEN` (bearer). From the console (above) or `oc whoami -t`.
- **password** — `OPENSHIFT_USERNAME` + `OPENSHIFT_PASSWORD` against the cluster's built-in OAuth server (HTPasswd / LDAP / any challenge-capable local IdP). The server runs the same request-token flow `oc login -u … -p …` uses, caches the token at `~/.mcp-openshift/token.json` (0600), and re-logs in on expiry. **The password is sent only to your cluster's OAuth endpoint** and is never logged or written to disk.

**TLS:** clusters usually use a private CA — set `OPENSHIFT_CA_CERT` to the CA bundle, or (dev only) `OPENSHIFT_INSECURE_TLS=true` to skip verification.

## Safe by default

Enforced by [`src/security.ts`](src/security.ts) — defence in depth on top of your account's cluster RBAC:

- **`OPENSHIFT_MODE`** — `read-only` (default) → `read-write` → `admin`. Tools above the mode aren't registered.
- **`OPENSHIFT_NAMESPACE_ALLOWLIST` / `OPENSHIFT_PROTECTED_NAMESPACES`** — confine writes to named namespaces; system namespaces (`kube-*`, `openshift`, `openshift-*`, `default`) are readable but never mutable.
- **`OPENSHIFT_ALLOW_APPLY`** — creating/updating resources needs this flag on top of read-write, plus a human confirmation.
- **`OPENSHIFT_ALLOW_DELETE`** — deletes need admin mode plus this flag, plus confirmation.
- **`OPENSHIFT_DRY_RUN`** — sends writes with Kubernetes `dryRun=All`: validated and admission-checked, but nothing persists.
- **Human-in-the-loop** — apply, delete, and scale-to-zero pause and ask a person to approve via MCP elicitation.
- **`OPENSHIFT_AUDIT_LOG`** — a JSON audit line per guarded op on stderr; **Secret values are redacted** from all output.

There is a bundled skill, [`openshift-safe-operations`](.claude/skills/openshift-safe-operations/SKILL.md), that teaches an agent how to authenticate (including from the browser console), the safety rules, and the standard triage/operate workflows. See also [SECURITY.md](SECURITY.md).

## Developing

```bash
npm install
npm run build
# list the tools without a live cluster:
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | OPENSHIFT_SERVER=https://x:6443 OPENSHIFT_TOKEN=x node dist/index.js
npm test
```

## Licence

MIT
