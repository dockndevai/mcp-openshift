# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
