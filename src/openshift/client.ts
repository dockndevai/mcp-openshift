/**
 * Thin REST client for an OpenShift / Kubernetes cluster.
 *
 * Talks to the API server over HTTPS with a bearer token (from auth.ts), honouring a private-CA TLS
 * dispatcher. A 401 invalidates the cached token and retries once (so an expired password token
 * transparently re-logs in). Secret values are redacted (src/redact.ts) before anything reaches the model.
 *
 * Reads cover core Kubernetes and OpenShift resources; writes are limited and deliberate (scale,
 * rollout restart, server-side apply); deletes live behind admin mode + a flag + confirmation.
 */
import type { Connection } from "../config.js";
import { createTokenProvider, type TokenProvider } from "./auth.js";
import { redactSecret } from "../redact.js";
import { makeDispatcher } from "./tls.js";

export class OpenShiftError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: string,
  ) {
    super(message);
    this.name = "OpenShiftError";
  }
}

/** Common kinds → their API group/version, plural resource, and scope. */
export interface KindInfo {
  apiVersion: string;
  resource: string;
  namespaced: boolean;
}
const KINDS: Record<string, KindInfo> = {
  pod: { apiVersion: "v1", resource: "pods", namespaced: true },
  service: { apiVersion: "v1", resource: "services", namespaced: true },
  configmap: { apiVersion: "v1", resource: "configmaps", namespaced: true },
  secret: { apiVersion: "v1", resource: "secrets", namespaced: true },
  namespace: { apiVersion: "v1", resource: "namespaces", namespaced: false },
  event: { apiVersion: "v1", resource: "events", namespaced: true },
  persistentvolumeclaim: { apiVersion: "v1", resource: "persistentvolumeclaims", namespaced: true },
  serviceaccount: { apiVersion: "v1", resource: "serviceaccounts", namespaced: true },
  node: { apiVersion: "v1", resource: "nodes", namespaced: false },
  deployment: { apiVersion: "apps/v1", resource: "deployments", namespaced: true },
  replicaset: { apiVersion: "apps/v1", resource: "replicasets", namespaced: true },
  statefulset: { apiVersion: "apps/v1", resource: "statefulsets", namespaced: true },
  daemonset: { apiVersion: "apps/v1", resource: "daemonsets", namespaced: true },
  job: { apiVersion: "batch/v1", resource: "jobs", namespaced: true },
  cronjob: { apiVersion: "batch/v1", resource: "cronjobs", namespaced: true },
  ingress: { apiVersion: "networking.k8s.io/v1", resource: "ingresses", namespaced: true },
  deploymentconfig: { apiVersion: "apps.openshift.io/v1", resource: "deploymentconfigs", namespaced: true },
  route: { apiVersion: "route.openshift.io/v1", resource: "routes", namespaced: true },
  build: { apiVersion: "build.openshift.io/v1", resource: "builds", namespaced: true },
  buildconfig: { apiVersion: "build.openshift.io/v1", resource: "buildconfigs", namespaced: true },
  imagestream: { apiVersion: "image.openshift.io/v1", resource: "imagestreams", namespaced: true },
  project: { apiVersion: "project.openshift.io/v1", resource: "projects", namespaced: false },
};

/** Aliases for kinds people commonly abbreviate. */
const ALIASES: Record<string, string> = { pvc: "persistentvolumeclaim", ns: "namespace", sa: "serviceaccount", cm: "configmap", svc: "service" };

/** Kinds whose own name IS a namespace: acting on one acts on that namespace and everything in it. */
const NAMESPACE_RESOURCES = new Set(["namespaces", "projects", "projectrequests"]);
export function isNamespaceKind(info: KindInfo): boolean {
  return NAMESPACE_RESOURCES.has(info.resource);
}

/** The table entry for a user-supplied kind ("Deployment", "deployment", "deployments", "ingresses", "pvc"), if known. */
function lookupKind(kind: string): KindInfo | undefined {
  const k = kind.trim().toLowerCase();
  const alias = ALIASES[k];
  if (alias) return KINDS[alias];
  return KINDS[k] ?? KINDS[k.replace(/(es|s)$/, "")] ?? KINDS[k.replace(/s$/, "")];
}

/**
 * Resolve a user-supplied kind to its API info. A kind that is not in the table is an error: guessing a plural and
 * core `v1` addressed the wrong API path for any custom resource (and a wrong guess can hit a different object).
 */
export function resolveKind(kind: string): KindInfo {
  const info = lookupKind(kind);
  if (!info) {
    throw new OpenShiftError(
      400,
      `Unknown kind '${kind}'. Supported kinds: ${Object.keys(KINDS).join(", ")}. ` +
        "Custom resources can be created or updated with apply_resource, which resolves the kind from the manifest's apiVersion.",
    );
  }
  return info;
}

/** `v1`, `apps/v1`, `route.openshift.io/v1`: a DNS-style group, then a version. Nothing that can alter a request path. */
const API_VERSION = /^([a-z0-9]([-a-z0-9.]*[a-z0-9])?\/)?[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
export function assertApiVersion(apiVersion: string): void {
  if (!API_VERSION.test(apiVersion)) {
    throw new OpenShiftError(400, `Invalid apiVersion '${apiVersion}': expected 'v1' or '<group>/<version>' (e.g. apps/v1).`);
  }
}

function apiRoot(apiVersion: string): string {
  return apiVersion.includes("/") ? `/apis/${apiVersion}` : `/api/${apiVersion}`;
}
function collectionPath(apiVersion: string, resource: string, ns?: string): string {
  const root = apiRoot(apiVersion);
  return ns ? `${root}/namespaces/${encodeURIComponent(ns)}/${resource}` : `${root}/${resource}`;
}
function itemPath(apiVersion: string, resource: string, name: string, ns?: string): string {
  return `${collectionPath(apiVersion, resource, ns)}/${encodeURIComponent(name)}`;
}

type KObj = Record<string, unknown> & { kind?: string; metadata?: Record<string, unknown> };

const isSecrets = (info: KindInfo) => info.resource === "secrets";

/** `uid@resourceVersion` of an object, or undefined when either is missing. */
export function versionToken(obj: KObj | undefined): string | undefined {
  const m = (obj?.metadata ?? {}) as { uid?: string; resourceVersion?: string };
  return m.uid && m.resourceVersion ? `${m.uid}@${m.resourceVersion}` : undefined;
}

/** Inverse of {@link versionToken}. */
export function parseVersionToken(token: string | undefined): { uid: string; resourceVersion: string } | undefined {
  if (!token) return undefined;
  const i = token.indexOf("@");
  if (i <= 0 || i === token.length - 1) return undefined;
  return { uid: token.slice(0, i), resourceVersion: token.slice(i + 1) };
}

export interface ApplyResult {
  kind?: string;
  name?: string;
  namespace?: string;
  resourceVersion?: string;
}

export class OpenShiftClient {
  private readonly server: string;
  private readonly timeoutMs: number;
  readonly maxResults: number;
  private readonly tokens: TokenProvider;
  private readonly dispatcher: ReturnType<typeof makeDispatcher>;
  /** Discovery results per apiVersion (resource lists never change within a session in a way that matters here). */
  private readonly discovered = new Map<string, Promise<Array<{ name: string; kind: string; namespaced: boolean }>>>();

  constructor(conn: Connection) {
    this.server = conn.server;
    this.timeoutMs = conn.timeoutMs;
    this.maxResults = conn.maxResults;
    this.tokens = createTokenProvider(conn);
    this.dispatcher = makeDispatcher(conn.caCertPath, conn.insecureTLS);
  }

  /**
   * API info for a kind. Kinds in the table resolve locally; any other kind is resolved by API discovery against the
   * given apiVersion (the manifest's, for apply), and is an error when there is none or the group does not serve it.
   */
  async kindInfo(kind: string, apiVersion?: string): Promise<KindInfo> {
    const known = lookupKind(kind);
    // A kind from the table is used as is unless the caller names a different group/version for it (e.g. a custom
    // resource that reuses a common kind name): then the API server says what that group serves.
    if (known && (!apiVersion || apiVersion === known.apiVersion)) return known;
    if (!apiVersion) return resolveKind(kind); // throws the "unknown kind" error
    assertApiVersion(apiVersion);
    let list = this.discovered.get(apiVersion);
    if (!list) {
      list = this.json<{ resources?: Array<{ name: string; kind: string; namespaced: boolean }> }>(apiRoot(apiVersion)).then(
        (r) => r.resources ?? [],
      );
      list.catch(() => this.discovered.delete(apiVersion));
      this.discovered.set(apiVersion, list);
    }
    const hit = (await list).find((r) => r.kind === kind && !r.name.includes("/"));
    if (!hit) throw new OpenShiftError(400, `Kind '${kind}' is not served by ${apiVersion}.`);
    return { apiVersion, resource: hit.name, namespaced: hit.namespaced };
  }

  /**
   * The namespace a call acts on, which is what the policy must check. It is not always the `namespace` argument:
   * a namespace / project (or project request) is cluster-scoped and its own name is the namespace it affects, and a
   * cluster-scoped kind affects no namespace. Throws for an unknown kind, so scope is never guessed.
   */
  async targetNamespace(kind: string, name: string | undefined, ns: string | undefined, apiVersion?: string): Promise<string | undefined> {
    const info = await this.kindInfo(kind, apiVersion);
    if (isNamespaceKind(info)) return name || undefined;
    return info.namespaced ? ns || undefined : undefined;
  }

  async ensureAuth(): Promise<void> {
    await this.tokens.getToken();
  }

  private async raw(path: string, init: RequestInit & { headers?: Record<string, string> } = {}, retry = true): Promise<Response> {
    const token = await this.tokens.getToken();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.server}${path}`, {
        ...init,
        signal: controller.signal,
        // undici-specific TLS dispatcher; not in the DOM RequestInit type.
        dispatcher: this.dispatcher,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
          ...(init.headers ?? {}),
        },
      } as RequestInit);
      if (res.status === 401 && retry) {
        this.tokens.invalidate();
        clearTimeout(timer);
        return this.raw(path, init, false);
      }
      return res;
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new OpenShiftError(504, `The cluster did not respond within ${this.timeoutMs / 1000}s.`);
      }
      throw new OpenShiftError(0, err instanceof Error ? err.message : String(err));
    } finally {
      clearTimeout(timer);
    }
  }

  private async json<T>(path: string, init?: RequestInit & { headers?: Record<string, string> }): Promise<T> {
    const res = await this.raw(path, init);
    const text = await res.text();
    if (!res.ok) {
      let detail = res.statusText;
      try {
        detail = (JSON.parse(text) as { message?: string }).message ?? detail;
      } catch {
        /* non-JSON error body */
      }
      throw new OpenShiftError(res.status, detail, text);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }

  // ---- identity ----
  async whoami(): Promise<Record<string, unknown>> {
    try {
      const u = await this.json<KObj>("/apis/user.openshift.io/v1/users/~");
      const m = (u.metadata ?? {}) as { name?: string };
      return { username: m.name, groups: (u as { groups?: string[] }).groups ?? [] };
    } catch {
      const r = await this.json<{ status?: { userInfo?: unknown } }>("/apis/authentication.k8s.io/v1/selfsubjectreviews", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiVersion: "authentication.k8s.io/v1", kind: "SelfSubjectReview" }),
      });
      return { userInfo: r.status?.userInfo };
    }
  }

  // ---- generic read ----
  async listProjects(): Promise<Array<Record<string, unknown>>> {
    const data = await this.json<{ items?: KObj[] }>("/apis/project.openshift.io/v1/projects");
    return (data.items ?? []).map((p) => {
      const m = (p.metadata ?? {}) as { name?: string; annotations?: Record<string, string> };
      return {
        name: m.name,
        displayName: m.annotations?.["openshift.io/display-name"],
        phase: (p as { status?: { phase?: string } }).status?.phase,
      };
    });
  }

  /** List a resource by kind (namespaced or cluster-scoped), with optional selector. */
  async listByKind(kind: string, ns?: string, opts: { labelSelector?: string; limit?: number } = {}): Promise<KObj> {
    const info = resolveKind(kind);
    const q = new URLSearchParams();
    q.set("limit", String(Math.min(this.maxResults, opts.limit ?? this.maxResults)));
    if (opts.labelSelector) q.set("labelSelector", opts.labelSelector);
    const path = `${collectionPath(info.apiVersion, info.resource, info.namespaced ? ns : undefined)}?${q.toString()}`;
    return redactSecret(await this.json<KObj>(path), isSecrets(info));
  }

  async getByKind(kind: string, name: string, ns?: string): Promise<KObj> {
    const info = resolveKind(kind);
    return redactSecret(
      await this.json<KObj>(itemPath(info.apiVersion, info.resource, name, info.namespaced ? ns : undefined)),
      isSecrets(info),
    );
  }

  async podLogs(ns: string, name: string, opts: { container?: string; tailLines?: number; previous?: boolean } = {}): Promise<string> {
    const q = new URLSearchParams();
    if (opts.container) q.set("container", opts.container);
    q.set("tailLines", String(Math.min(5000, opts.tailLines ?? 200)));
    if (opts.previous) q.set("previous", "true");
    const res = await this.raw(`/api/v1/namespaces/${encodeURIComponent(ns)}/pods/${encodeURIComponent(name)}/log?${q.toString()}`);
    const text = await res.text();
    if (!res.ok) throw new OpenShiftError(res.status, text || res.statusText, text);
    return text;
  }

  // ---- writes ----
  /** Scale a Deployment or DeploymentConfig via its scale subresource (merge patch). */
  async scale(kind: string, ns: string, name: string, replicas: number, dryRun: boolean): Promise<KObj> {
    const info = resolveKind(kind);
    const path = `${itemPath(info.apiVersion, info.resource, name, ns)}/scale${dryRun ? "?dryRun=All" : ""}`;
    return redactSecret(
      await this.json<KObj>(path, {
        method: "PATCH",
        headers: { "Content-Type": "application/merge-patch+json" },
        body: JSON.stringify({ spec: { replicas } }),
      }),
      isSecrets(info),
    );
  }

  /** Trigger a rolling restart by stamping the pod template (strategic merge). */
  async rolloutRestart(ns: string, name: string, dryRun: boolean): Promise<KObj> {
    const path = `${itemPath("apps/v1", "deployments", name, ns)}${dryRun ? "?dryRun=All" : ""}`;
    return this.json<KObj>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/strategic-merge-patch+json" },
      body: JSON.stringify({
        spec: { template: { metadata: { annotations: { "kubectl.kubernetes.io/restartedAt": new Date().toISOString() } } } },
      }),
    });
  }

  /** Server-side apply a manifest (create or update). Returns the applied object's identity. */
  async apply(manifest: KObj, dryRun: boolean): Promise<ApplyResult> {
    const apiVersion = (manifest.apiVersion as string) || "v1";
    const kind = (manifest.kind as string) || "";
    if (!kind) throw new OpenShiftError(400, "Manifest is missing 'kind'.");
    const info = await this.kindInfo(kind, apiVersion);
    const m = (manifest.metadata ?? {}) as { name?: string; namespace?: string };
    if (!m.name) throw new OpenShiftError(400, "Manifest metadata.name is required.");
    if (info.namespaced && !m.namespace) throw new OpenShiftError(400, `Manifest metadata.namespace is required for ${kind}.`);
    const ns = info.namespaced ? m.namespace : undefined;
    const q = new URLSearchParams({ fieldManager: "mcp-openshift", force: "true" });
    if (dryRun) q.set("dryRun", "All");
    const path = `${itemPath(apiVersion, info.resource, m.name, ns)}?${q.toString()}`;
    const out = await this.json<KObj>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/apply-patch+yaml" },
      body: JSON.stringify(manifest),
    });
    const om = (out.metadata ?? {}) as { name?: string; namespace?: string; resourceVersion?: string };
    return { kind: out.kind as string, name: om.name, namespace: om.namespace, resourceVersion: om.resourceVersion };
  }

  // ---- destructive ----
  /**
   * Delete a resource. When `expectedVersion` (a token from {@link resourceVersion}) is given, it is sent as
   * DeleteOptions preconditions (uid + resourceVersion), so the API server refuses (409) if the object was
   * replaced or modified after the human approved it.
   */
  async deleteResource(
    kind: string,
    name: string,
    ns: string | undefined,
    dryRun: boolean,
    expectedVersion?: string,
  ): Promise<Record<string, unknown>> {
    const info = resolveKind(kind);
    const path = `${itemPath(info.apiVersion, info.resource, name, info.namespaced ? ns : undefined)}${dryRun ? "?dryRun=All" : ""}`;
    const pin = parseVersionToken(expectedVersion);
    // The API server may answer a delete with the deleted object, so it is redacted like any other read.
    const out = pin
      ? await this.json<Record<string, unknown>>(path, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            apiVersion: "v1",
            kind: "DeleteOptions",
            preconditions: { uid: pin.uid, resourceVersion: pin.resourceVersion },
          }),
        })
      : await this.json<Record<string, unknown>>(path, { method: "DELETE" });
    return redactSecret(out, isSecrets(info));
  }

  /**
   * Version token for an exact object: `metadata.uid@metadata.resourceVersion`, or undefined if it does not exist
   * (404). Any write to the object (including status updates by controllers) bumps resourceVersion, so a busy
   * object may need the action re-issued; that fails closed. The uid distinguishes a delete + recreate under the
   * same name. Other errors (401/403, transport) throw.
   */
  async resourceVersion(
    kind: string,
    name: string,
    ns: string | undefined,
    apiVersion?: string,
  ): Promise<string | undefined> {
    const info = await this.kindInfo(kind, apiVersion);
    try {
      const obj = await this.json<KObj>(
        itemPath(apiVersion || info.apiVersion, info.resource, name, info.namespaced ? ns : undefined),
      );
      return versionToken(obj);
    } catch (err) {
      if (err instanceof OpenShiftError && err.status === 404) return undefined;
      throw err;
    }
  }
}
