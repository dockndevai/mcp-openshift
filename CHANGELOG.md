# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-11-09

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  high/critical advisories; no `npm audit fix` was needed.
- Took safe in-range patch bumps: `undici` ^8.12.2 8.12.3 → 8.12.4, `vitest` ^5.0.5
  5.0.5 → 5.1.0.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.2.4] - 2026-11-02

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  vulnerabilities both before and after this pass (no high/critical advisories to fix).
- Took a safe in-range patch bump: `@types/node` ^26.5.0 26.6.5 → 26.6.6.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.2.3] - 2026-10-26

### Security
- `npm audit --audit-level=high` reported 1 high (`body-parser` DoS via trailing bytes after a
  compressed request body) and 1 moderate (`fast-uri` scheme/host confusion, multiple advisories).
  `npm audit fix` resolved both via transitive lockfile bumps (`body-parser` 2.3.0 → 2.4.0,
  `fast-uri` 3.1.8 → 3.1.9) — no direct dependency range changed.

### Changed
- Took safe in-range patch bumps (ranges unchanged): `@modelcontextprotocol/sdk` 1.32.1 → 1.32.2,
  `undici` 8.12.2 → 8.12.3.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` reports 0 vulnerabilities.

## [0.2.2] - 2026-10-19

### Changed
- Routine dependency/security maintenance. `npm audit --audit-level=high` reported 0
  vulnerabilities both before and after this pass (no high/critical advisories to fix).
- Took safe in-range patch bumps: `undici` ^8.10.2 → ^8.12.2, `zod` ^4.6.5 → ^4.6.7,
  `vitest` ^5.0.1 → ^5.0.5.
- No direct dependency crossed a major version boundary; `npm run typecheck`, `npm run build`,
  and `npm test` all pass; final `npm audit` is clean.

## [0.2.1] - 2026-10-12

### Security
- Dependency/security maintenance: `npm audit fix` resolved 6 advisories (1 critical: `proxy-addr`
  IP-spoofing via IPv4-mapped IPv6 trust subnet; 2 high: `@modelcontextprotocol/sdk` OAuth client
  credential-leak to an attacker-chosen authorization server, `source-map-js` event-loop DoS; 3
  moderate: `fast-uri`, `hono`, `ip-address`) via transitive lockfile updates only — no direct
  dependency range changed.
- Routine patch bumps for `@types/node`, `tsx`, `undici`, `vitest`, `zod` within their existing
  semver ranges. `npm audit` now reports 0 vulnerabilities.

## [0.2.0] - 2026-09-27

### Added
- **Optional AI risk guard (laya-guard).** `apply_resource` and `delete_resource` can consult a local
  [laya-guard](https://github.com/dockndevai/laya-guard) daemon that classifies the operation
  allow / confirm / block before it runs. Runs *after* the apply/delete gates and can only *tighten*,
  never grant; fails closed. Off by default (`OPENSHIFT_GUARD_MODE=monitor|enforce`).

## [0.1.0] - 2026-09-19

### Added
- Initial release: a safe-by-default MCP server for OpenShift / Kubernetes. 10 tools across
  read/read-write/admin: `whoami`, `list_projects`, `list_resources`, `get_resource`, `pod_logs`,
  `list_events`; `scale`, `rollout_restart`, `apply_resource`; and `delete_resource`.
- **Two auth methods**, auto-detected: a bearer **token** (`OPENSHIFT_TOKEN`, e.g. from the web
  console's *Copy login command → Display Token*), or **username/password** against the cluster's
  local identity provider (`OPENSHIFT_USERNAME`/`OPENSHIFT_PASSWORD`), which runs the OpenShift OAuth
  request-token flow, caches the token on disk (0600), and re-logs in on expiry. Private-CA and
  insecure-TLS options for real clusters.
- Security model: access modes (read-only/read-write/admin), namespace allowlist and protected
  namespaces (system/`openshift-*` read-only), an **apply gate** (`OPENSHIFT_ALLOW_APPLY`) and a
  **delete gate** (`OPENSHIFT_ALLOW_DELETE`), Kubernetes `dryRun=All` support, JSON audit logging,
  and **Secret redaction**.
- **Human-in-the-loop confirmation** via MCP elicitation on apply, delete, and scale-to-zero.
- Bundled skill `openshift-safe-operations` documenting browser-console/username-password auth, the
  safety rules, and standard triage/operate workflows.
- MCP tool annotations derived from each tool's capability, with a test keeping them consistent.
