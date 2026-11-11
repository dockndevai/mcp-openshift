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
- **Require a human for destructive ops.** Set `OPENSHIFT_REQUIRE_HUMAN_APPROVAL=true` so
  `delete_resource`, `apply_resource` and scale-to-zero are refused when the client cannot show an
  approval prompt. Each approval is bound to the exact tool and arguments (fingerprint) and to the target
  object's `metadata.uid` + `metadata.resourceVersion` (for `apply_resource`, the existing object's, or
  "absent" when it will be created); if the object changed while the human was deciding, the action is
  refused. `delete_resource` also sends the approved uid and resourceVersion to the API server as delete
  preconditions. Deleting a namespace or project also asks the human to type its name. Any write to the
  object, including controller status updates, changes its resourceVersion, so a busy object may need the
  action re-issued. Approval receipts are written to the audit log (`"audit":"approval"`, with `approvedBy`
  = `human` or `flag-only`).
- **Preview with dry-run.** `OPENSHIFT_DRY_RUN=true` sends writes with Kubernetes `dryRun=All`: the
  API validates and runs admission but persists nothing.
- **Secrets are redacted.** In every response that can carry a Secret (`get_resource`, `list_resources`, and the
  object returned by `delete_resource` / `scale`), `data` and `stringData` values are replaced with
  `<redacted, N bytes>` (keys are kept) and the `kubectl.kubernetes.io/last-applied-configuration` annotation,
  which holds a copy of the values, is redacted. List items are redacted by the kind you asked for, since the
  API omits `kind` on them. `apply_resource` returns only the applied object's identity.
- **Log output is redacted, best effort.** Output from `pod_logs` is scanned, and credential-shaped text is masked before it reaches the model.
  This is **heuristic defence in depth, not a guarantee**: it cannot know what a workload considers secret. It is on
  by default; `OPENSHIFT_REDACT_LOGS=false` (or `0`, `no`, `off`) turns it off (any other value, including a typo, leaves it on). What it masks
  (each as `[REDACTED]`, `[REDACTED:<kind>]` or `[REDACTED PRIVATE KEY]`, with the rest of the line kept):
  - PEM private-key blocks (RSA, EC, OpenSSH, encrypted, PGP, plain `PRIVATE KEY`), including a block that is
    unterminated or whose `BEGIN` line was cut off by `tail` (its bare base64 body lines are dropped);
    certificates and public keys are left alone.
  - The value of any `key=value`, `key: value`, `"key":"value"` or `--flag value` whose key **ends in**
    `password`, `passwd`, `passphrase`, `secret`, `token`, `credential(s)`, `authorization`, `api_key`, `access_key`,
    `secret_key`, `secret_access_key`, `private_key`, `signing_key`, `encryption_key`, `master_key`, `account_key`, `auth_key`,
    `primary_key`, `secondary_key` (case-insensitive, `_`/`-` optional), plus `X-Amz-Signature` and `sig`. For
    `Authorization:` the scheme (`Bearer`, `Basic`, ...) is kept and the credential after it is masked.
  - `Bearer <token>` anywhere (the token must contain a digit, so prose like "bearer authentication" is untouched).
  - The password in `scheme://user:PASSWORD@host` URLs (database and registry DSNs, `https://x-access-token:...@github.com`).
  - Well-known token shapes, with no key name needed: JWTs (which includes Kubernetes service-account tokens), OpenShift
    `sha256~` tokens, AWS access key ids, GCP API keys and OAuth tokens, GitHub, GitLab, Slack, Stripe, npm, Vault and
    SendGrid tokens.
  What it does **not** catch: a secret with no recognisable shape and no telling key name (a bare random password, a
  raw AWS secret access key on its own, a password in a sentence), secrets split across lines (other than PEM
  blocks), encoded or obfuscated secrets, cookies and session ids, scheme-less `user:pass@host` DSNs, and personal data.
  Deliberate trade-offs: the value after a secret-named key is masked even when it is only a reference name
  (`imagePullSecret: regcred`); an unquoted value ends at whitespace, a comma, `;`, `&`, `<`, `>` or a quote, so a password
  containing one of those is only partly masked; and `null`/`true`/`none`-style words, `$VAR` references and
  already-redacted markers are left as they are. The pass is line oriented and linear in the output size (no
  backtracking-prone patterns; a 1 MB single line is covered by a test). With `OPENSHIFT_REDACT_LOGS=false` the logs are returned exactly as the workload produced them.
- **TLS.** Prefer `OPENSHIFT_CA_CERT` (trust the cluster CA). `OPENSHIFT_INSECURE_TLS=true` disables
  certificate verification and MITM protection — development clusters only.

## Limitations

- Namespace allowlist/protection is enforced on the namespace a call acts on. For a namespace or project
  (kind `namespace` / `project`, including a `Namespace`, `Project` or `ProjectRequest` manifest) that is the
  object's own name, whatever `namespace` argument accompanies it; otherwise it is the `namespace` argument,
  and for `apply_resource` the manifest's `metadata.namespace` (required for namespaced kinds).
- `get_resource`, `list_resources`, `delete_resource` and `scale` accept the kinds in the built-in table; any other
  kind is rejected with an "Unknown kind" error rather than guessed. `apply_resource` resolves other kinds by
  API discovery on the manifest's `apiVersion`. `apiVersion` must be `v1` or `<group>/<version>`.
- `apply_resource` trusts the manifest you pass; it is a server-side apply as your account. There is
  no content filtering beyond the human-confirmation prompt and dry-run. Keep `OPENSHIFT_ALLOW_APPLY`
  off unless you need it.
- This is not a full `oc`/`kubectl` — there is no exec/attach/port-forward/watch in this version
  (those need a streaming transport); it favours safe REST reads and deliberate writes.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
