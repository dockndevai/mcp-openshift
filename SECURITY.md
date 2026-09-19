# Security

`mcp-openshift` gives an AI agent access to an OpenShift / Kubernetes cluster. Treat it like any
privileged automation and grant it the least it needs.

## Principles

- **Start read-only.** Leave `OPENSHIFT_MODE=read-only` until you need to change something. In
  read-only mode only observe tools are registered — scale/apply/delete aren't exposed to the model.
- **The cluster's RBAC is the primary control.** These flags are defence in depth. The real boundary
  is the token/account the server authenticates as: it carries the user's roles and role bindings.
  Use a service account or user with the **least role** that works — a view-only account means even a
  bug or a prompt injection cannot mutate anything.
- **Credentials.** A token is sent as a bearer header to the API server. A username/password is sent
  **only** to the cluster's own OAuth endpoint (the same request-token flow `oc login -u -p` uses);
  it is never logged and never written to disk — only the resulting token is cached, at
  `~/.mcp-openshift/token.json` with mode 0600.
- **Protect namespaces.** `OPENSHIFT_PROTECTED_NAMESPACES` (default `kube-*`, `openshift`,
  `openshift-*`, `default`) can be read but never mutated. `OPENSHIFT_NAMESPACE_ALLOWLIST` confines
  writes/deletes to named namespaces.
- **Gate mutations.** Creating/updating (`apply_resource`) needs `OPENSHIFT_ALLOW_APPLY=true`;
  deleting needs `admin` mode **and** `OPENSHIFT_ALLOW_DELETE=true`. Both also prompt a human to
  confirm via MCP elicitation, as does scaling a workload to zero.
- **Preview with dry-run.** `OPENSHIFT_DRY_RUN=true` sends writes with Kubernetes `dryRun=All`: the
  API validates and runs admission but persists nothing.
- **Secrets are redacted.** Secret `data` values never reach the model — only the keys and byte sizes.
- **TLS.** Prefer `OPENSHIFT_CA_CERT` (trust the cluster CA). `OPENSHIFT_INSECURE_TLS=true` disables
  certificate verification and MITM protection — development clusters only.

## Limitations

- Namespace allowlist/protection is enforced on the namespace a call names. `apply_resource` derives
  the namespace from the manifest's `metadata.namespace`.
- `apply_resource` trusts the manifest you pass; it is a server-side apply as your account. There is
  no content filtering beyond the human-confirmation prompt and dry-run. Keep `OPENSHIFT_ALLOW_APPLY`
  off unless you need it.
- This is not a full `oc`/`kubectl` — there is no exec/attach/port-forward/watch in this version
  (those need a streaming transport); it favours safe REST reads and deliberate writes.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
