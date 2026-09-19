/**
 * Configuration from environment variables.
 *
 * Connects to an OpenShift / Kubernetes cluster's REST API with a bearer token. Two ways to get that
 * token, chosen automatically in this priority order (override with OPENSHIFT_AUTH):
 *
 *   1. **token** — OPENSHIFT_TOKEN, a pre-obtained bearer token. Simplest. Get one from the web
 *      console (top-right user menu → *Copy login command* → *Display Token*) or `oc whoami -t`.
 *   2. **password** — OPENSHIFT_USERNAME + OPENSHIFT_PASSWORD against the cluster's built-in OAuth
 *      server (HTPasswd / LDAP / any challenge-capable local identity provider). The server performs
 *      the same request-token flow `oc login -u … -p …` uses, caches the token on disk, and re-logs
 *      in when it expires. The password is only ever sent to your cluster's OAuth endpoint.
 *
 * TLS: clusters often use a private CA. Point OPENSHIFT_CA_CERT at the CA bundle, or set
 * OPENSHIFT_INSECURE_TLS=true to skip verification (development only — it disables MITM protection).
 */
import { homedir } from "node:os";
import { join } from "node:path";
import type { AccessMode, SecurityConfig } from "./security.js";

export type AuthMode = "token" | "password";

export interface OpenShiftAuth {
  mode: AuthMode;
  /** Static bearer token (mode "token"). */
  token?: string;
  /** Username + password for the OAuth request-token flow (mode "password"). */
  username?: string;
  password?: string;
  /** OAuth client id used for the challenge flow. OpenShift ships `openshift-challenging-client`. */
  oauthClientId: string;
  /** Where the cached password-obtained token is stored. */
  tokenCachePath: string;
}

export interface Connection {
  /** Kubernetes API server URL, e.g. https://api.cluster.example.com:6443 */
  server: string;
  auth: OpenShiftAuth;
  /** Path to a PEM CA bundle that signs the API server / OAuth server certs. */
  caCertPath?: string;
  /** Skip TLS verification (development only). */
  insecureTLS: boolean;
  timeoutMs: number;
  maxResults: number;
}

export interface AppConfig {
  connection: Connection;
  security: SecurityConfig;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return ["1", "true", "yes", "on"].includes(v.toLowerCase());
}

function list(name: string): string[] {
  const v = process.env[name];
  if (!v) return [];
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

function parseMode(): AccessMode {
  const raw = (process.env.OPENSHIFT_MODE ?? "read-only").toLowerCase();
  if (raw === "read-only" || raw === "read-write" || raw === "admin") return raw;
  throw new Error(`Invalid OPENSHIFT_MODE '${raw}'. Expected one of: read-only, read-write, admin.`);
}

function resolveAuthMode(): AuthMode {
  const explicit = process.env.OPENSHIFT_AUTH?.trim().toLowerCase();
  if (explicit === "token" || explicit === "password") return explicit;
  if (explicit) throw new Error(`Invalid OPENSHIFT_AUTH '${explicit}'. Expected one of: token, password.`);
  if (process.env.OPENSHIFT_TOKEN?.trim()) return "token";
  return "password";
}

/** System namespaces that may be read but never mutated, unless the operator overrides the list. */
const DEFAULT_PROTECTED = [
  "kube-system",
  "kube-public",
  "kube-node-lease",
  "default",
  "openshift",
  "openshift-infra",
  "openshift-config",
  "openshift-apiserver",
  "openshift-authentication",
  "openshift-etcd",
  "openshift-kube-apiserver",
];

export function loadConfig(): AppConfig {
  const protectedRaw = list("OPENSHIFT_PROTECTED_NAMESPACES");
  return {
    connection: {
      server: (process.env.OPENSHIFT_SERVER || "").trim().replace(/\/$/, ""),
      auth: {
        mode: resolveAuthMode(),
        token: process.env.OPENSHIFT_TOKEN?.trim() || undefined,
        username: process.env.OPENSHIFT_USERNAME?.trim() || undefined,
        password: process.env.OPENSHIFT_PASSWORD ?? undefined,
        oauthClientId: process.env.OPENSHIFT_OAUTH_CLIENT?.trim() || "openshift-challenging-client",
        tokenCachePath:
          process.env.OPENSHIFT_TOKEN_CACHE?.trim() || join(homedir(), ".mcp-openshift", "token.json"),
      },
      caCertPath: process.env.OPENSHIFT_CA_CERT?.trim() || undefined,
      insecureTLS: bool("OPENSHIFT_INSECURE_TLS", false),
      timeoutMs: Number(process.env.OPENSHIFT_TIMEOUT_MS ?? 30000),
      maxResults: Math.max(1, Math.min(500, Number(process.env.OPENSHIFT_MAX_RESULTS ?? 100))),
    },
    security: {
      mode: parseMode(),
      namespaceAllowlist: list("OPENSHIFT_NAMESPACE_ALLOWLIST"),
      protectedNamespaces: (protectedRaw.length ? protectedRaw : DEFAULT_PROTECTED).map((s) => s.toLowerCase()),
      allowDelete: bool("OPENSHIFT_ALLOW_DELETE", false),
      allowApply: bool("OPENSHIFT_ALLOW_APPLY", false),
      dryRun: bool("OPENSHIFT_DRY_RUN", false),
      auditLog: bool("OPENSHIFT_AUDIT_LOG", true),
    },
  };
}

/** True when the configuration is complete enough to attempt a connection. */
export function hasCredentials(c: Connection): boolean {
  if (!c.server) return false;
  const a = c.auth;
  return a.mode === "token" ? Boolean(a.token) : Boolean(a.username && a.password !== undefined);
}

export function missingHint(c: Connection): string {
  if (!c.server) return "Set OPENSHIFT_SERVER to your cluster API URL (e.g. https://api.cluster.example.com:6443).";
  return c.auth.mode === "token"
    ? "Set OPENSHIFT_TOKEN (console → user menu → Copy login command → Display Token)."
    : "Set OPENSHIFT_USERNAME and OPENSHIFT_PASSWORD for your local identity provider (or use OPENSHIFT_TOKEN).";
}
