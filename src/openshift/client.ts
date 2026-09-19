/**
 * Thin REST client for an OpenShift / Kubernetes cluster.
 *
 * Talks to the API server over HTTPS with a bearer token (from auth.ts), honouring a private-CA TLS
 * dispatcher. A 401 invalidates the cached token and retries once (so an expired password token
 * transparently re-logs in). Secret `data` values are redacted before anything reaches the model.
 *
 * Reads cover core Kubernetes and OpenShift resources; writes are limited and deliberate (scale,
 * rollout restart, server-side apply); deletes live behind admin mode + a flag + confirmation.
 */
import type { Connection } from "../config.js";
import { createTokenProvider, type TokenProvider } from "./auth.js";
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
interface KindInfo {
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

/** Resolve a user-supplied kind ("Deployment", "deployment", "deployments") to its API info. */
export function resolveKind(kind: string): KindInfo {
  const k = kind.toLowerCase();
  return KINDS[k] ?? KINDS[k.replace(/s$/, "")] ?? { apiVersion: "v1", resource: `${k.replace(/s$/, "")}s`, namespaced: true };
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

/** Strip base64 secret values so credentials never reach the model; keep keys + sizes. */
function redactSecret(obj: KObj): KObj {
  if (obj.kind === "Secret" && obj.data && typeof obj.data === "object") {
    const data = obj.data as Record<string, string>;
    const red: Record<string, string> = {};
    for (const k of Object.keys(data)) red[k] = `<redacted, ${Buffer.from(data[k] ?? "", "base64").length} bytes>`;
    return { ...obj, data: red };
  }
  return obj;
}
function redactList(obj: KObj): KObj {
  if (Array.isArray((obj as { items?: unknown }).items)) {
    return { ...obj, items: ((obj as { items: KObj[] }).items).map(redactSecret) };
  }
  return obj;
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

  constructor(conn: Connection) {
    this.server = conn.server;
    this.timeoutMs = conn.timeoutMs;
    this.maxResults = conn.maxResults;
    this.tokens = createTokenProvider(conn);
    this.dispatcher = makeDispatcher(conn.caCertPath, conn.insecureTLS);
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
    return redactList(await this.json<KObj>(path));
  }

  async getByKind(kind: string, name: string, ns?: string): Promise<KObj> {
    const info = resolveKind(kind);
    return redactSecret(await this.json<KObj>(itemPath(info.apiVersion, info.resource, name, info.namespaced ? ns : undefined)));
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
    return this.json<KObj>(path, {
      method: "PATCH",
      headers: { "Content-Type": "application/merge-patch+json" },
      body: JSON.stringify({ spec: { replicas } }),
    });
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
    const info = resolveKind(kind);
    const m = (manifest.metadata ?? {}) as { name?: string; namespace?: string };
    if (!m.name) throw new OpenShiftError(400, "Manifest metadata.name is required.");
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
  async deleteResource(kind: string, name: string, ns: string | undefined, dryRun: boolean): Promise<Record<string, unknown>> {
    const info = resolveKind(kind);
    const path = `${itemPath(info.apiVersion, info.resource, name, info.namespaced ? ns : undefined)}${dryRun ? "?dryRun=All" : ""}`;
    return this.json<Record<string, unknown>>(path, { method: "DELETE" });
  }
}
