import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { OpenShiftClient, resolveKind } from "../src/openshift/client.js";
import { buildServer } from "../src/server.js";

const config = (allowlist: string[] = []): AppConfig => ({
  connection: {
    server: "https://api.test:6443",
    auth: { mode: "token", token: "t", oauthClientId: "c", tokenCachePath: "/dev/null" },
    insecureTLS: false,
    timeoutMs: 1000,
    maxResults: 10,
  },
  security: {
    mode: "admin",
    namespaceAllowlist: allowlist,
    protectedNamespaces: ["kube-system", "openshift-*"],
    allowApply: true,
    allowDelete: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
  },
});

async function connect(allowlist: string[] = []) {
  const { server } = buildServer(config(allowlist));
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");
const isError = (r: unknown) => (r as { isError?: boolean }).isError === true;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function stubBackend() {
  return {
    del: vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({ status: "Success" }),
    version: vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@1"),
    apply: vi.spyOn(OpenShiftClient.prototype, "apply").mockResolvedValue({ kind: "X", name: "x" }),
  };
}

/** Routes fetch by URL path; records every request. */
function stubFetch(routes: Record<string, unknown>) {
  const calls: Array<{ url: string; method: string }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? "GET" });
      const path = new URL(url).pathname;
      return path in routes
        ? new Response(JSON.stringify(routes[path]), { status: 200 })
        : new Response(JSON.stringify({ message: "not found" }), { status: 404 });
    }),
  );
  return calls;
}

describe("delete_resource: a namespace / project's own name is the namespace the policy checks", () => {
  for (const kind of ["namespace", "Namespace", "namespaces", "ns", "project", "Project", "projects"]) {
    it(`refuses to delete a protected namespace via kind '${kind}' with no namespace argument`, async () => {
      const b = stubBackend();
      const res = await (await connect()).callTool({ name: "delete_resource", arguments: { kind, name: "kube-system" } });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/protected/);
      expect(b.del).not.toHaveBeenCalled();
    });
  }

  it("honours wildcard protection (openshift-*) for a project", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "project", name: "openshift-monitoring" } });
    expect(text(res)).toMatch(/protected/);
    expect(b.del).not.toHaveBeenCalled();
  });

  it("is not fooled by a harmless `namespace` argument next to a protected name", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "project", name: "kube-system", namespace: "scratch" } });
    expect(text(res)).toMatch(/protected/);
    expect(b.del).not.toHaveBeenCalled();
  });

  it("enforces the allowlist on the project being deleted, and still deletes an allowed one", async () => {
    const b = stubBackend();
    const c = await connect(["shop"]);
    const denied = await c.callTool({ name: "delete_resource", arguments: { kind: "project", name: "billing" } });
    expect(text(denied)).toMatch(/allowlist/);
    expect(b.del).not.toHaveBeenCalled();
    const ok = await c.callTool({ name: "delete_resource", arguments: { kind: "project", name: "shop" } });
    expect(isError(ok)).toBe(false);
    expect(b.del).toHaveBeenCalledTimes(1);
  });

  it("an ordinary namespaced delete is unchanged (control)", async () => {
    const b = stubBackend();
    const res = await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "pod", name: "web-0", namespace: "shop" } });
    expect(isError(res)).toBe(false);
    expect(b.del).toHaveBeenCalledTimes(1);
  });
});

describe("apply_resource checks the namespace the object will really land in", () => {
  for (const kind of ["Namespace", "Project", "ProjectRequest"]) {
    it(`refuses a ${kind} manifest named after a protected namespace`, async () => {
      const b = stubBackend();
      const apiVersion = kind === "Namespace" ? "v1" : "project.openshift.io/v1";
      stubFetch({ "/apis/project.openshift.io/v1": { resources: [{ name: "projectrequests", kind: "ProjectRequest", namespaced: false }] } });
      const res = await (await connect()).callTool({
        name: "apply_resource",
        arguments: { manifest: { apiVersion, kind, metadata: { name: "kube-system", labels: { x: "y" } } } },
      });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/protected/);
      expect(b.apply).not.toHaveBeenCalled();
    });
  }

  it("enforces the allowlist on a Namespace manifest", async () => {
    const b = stubBackend();
    const res = await (await connect(["shop"])).callTool({
      name: "apply_resource",
      arguments: { manifest: { apiVersion: "v1", kind: "Namespace", metadata: { name: "billing" } } },
    });
    expect(text(res)).toMatch(/allowlist/);
    expect(b.apply).not.toHaveBeenCalled();
  });

  it("still applies into an allowed namespace (control)", async () => {
    const b = stubBackend();
    const res = await (await connect(["shop"])).callTool({
      name: "apply_resource",
      arguments: { manifest: { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "shop" } } },
    });
    expect(isError(res)).toBe(false);
    expect(b.apply).toHaveBeenCalledTimes(1);
  });

  it("rejects a namespaced manifest with no namespace instead of sending it", async () => {
    const calls = stubFetch({});
    for (const metadata of [{ name: "cfg" }, { name: "cfg", namespace: "" }]) {
      const res = await (await connect()).callTool({
        name: "apply_resource",
        arguments: { manifest: { apiVersion: "v1", kind: "ConfigMap", metadata } },
      });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/metadata\.namespace is required/);
    }
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  });
});

describe("apiVersion cannot rewrite the request path", () => {
  it("apply_resource rejects an apiVersion that would redirect the PATCH into another namespace", async () => {
    const calls = stubFetch({});
    const res = await (await connect()).callTool({
      name: "apply_resource",
      arguments: {
        manifest: {
          apiVersion: "v1/../../../api/v1/namespaces/kube-system/configmaps/cfg#",
          kind: "ConfigMap",
          metadata: { name: "cfg", namespace: "scratch" },
        },
      },
    });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/apiVersion/);
    expect(calls).toEqual([]);
  });

  for (const apiVersion of ["v1?x=1", "../v1", "a/b/c"]) {
    it(`rejects ${JSON.stringify(apiVersion)}`, async () => {
      const c = new OpenShiftClient(config().connection);
      stubFetch({});
      await expect(c.resourceVersion("pod", "p", "ns", apiVersion)).rejects.toThrow(/Invalid apiVersion/);
    });
  }
});

describe("unknown kinds fail clearly instead of hitting the wrong API path", () => {
  it("resolveKind keeps resolving known kinds, plurals, -es plurals and documented aliases", () => {
    expect(resolveKind("Deployment").resource).toBe("deployments");
    expect(resolveKind("deployments").resource).toBe("deployments");
    expect(resolveKind("ingresses")).toMatchObject({ apiVersion: "networking.k8s.io/v1", resource: "ingresses" });
    expect(resolveKind("pvc")).toMatchObject({ resource: "persistentvolumeclaims", namespaced: true });
    expect(resolveKind("projects")).toMatchObject({ apiVersion: "project.openshift.io/v1", namespaced: false });
    expect(resolveKind("node").namespaced).toBe(false);
  });

  it("resolveKind throws for a kind it does not know, naming it and the supported ones", () => {
    expect(() => resolveKind("Widget")).toThrow(/Unknown kind 'Widget'.*Supported kinds: pod/);
    expect(() => resolveKind("")).toThrow(/Unknown kind/);
  });

  it("delete_resource of a custom resource errors and sends nothing", async () => {
    const calls = stubFetch({});
    const res = await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "Widget", name: "w1", namespace: "shop" } });
    expect(isError(res)).toBe(true);
    expect(text(res)).toMatch(/Unknown kind 'Widget'/);
    expect(calls).toEqual([]);
  });

  it("get_resource and list_resources of an unknown kind error and send nothing", async () => {
    const calls = stubFetch({});
    const c = await connect();
    for (const [name, args] of [
      ["get_resource", { kind: "Widget", name: "w1", namespace: "shop" }],
      ["list_resources", { kind: "Widget", namespace: "shop" }],
    ] as const) {
      const res = await c.callTool({ name, arguments: args });
      expect(isError(res)).toBe(true);
      expect(text(res)).toMatch(/Unknown kind 'Widget'/);
    }
    expect(calls).toEqual([]);
  });
});

describe("apply_resource resolves a custom resource by discovery on the manifest's apiVersion", () => {
  const widgets = { resources: [{ name: "widgets", kind: "Widget", namespaced: true }, { name: "widgets/status", kind: "Widget", namespaced: true }] };

  it("uses the discovered plural and scope", async () => {
    const calls = stubFetch({
      "/apis/example.com/v1": widgets,
      "/apis/example.com/v1/namespaces/shop/widgets/w1": { kind: "Widget", metadata: { name: "w1", namespace: "shop", resourceVersion: "5" } },
    });
    const out = await new OpenShiftClient(config().connection).apply(
      { apiVersion: "example.com/v1", kind: "Widget", metadata: { name: "w1", namespace: "shop" } },
      false,
    );
    expect(out.name).toBe("w1");
    const patch = calls.find((c) => c.method === "PATCH");
    expect(new URL(patch!.url).pathname).toBe("/apis/example.com/v1/namespaces/shop/widgets/w1");
  });

  it("asks the API server what a group serves when a known kind name is used with another apiVersion", async () => {
    const calls = stubFetch({
      "/apis/extensions/v1beta1": { resources: [{ name: "ingresses", kind: "Ingress", namespaced: true }] },
      "/apis/extensions/v1beta1/namespaces/shop/ingresses/web": { kind: "Ingress", metadata: { name: "web", namespace: "shop" } },
    });
    await new OpenShiftClient(config().connection).apply({ apiVersion: "extensions/v1beta1", kind: "Ingress", metadata: { name: "web", namespace: "shop" } }, false);
    expect(calls.map((c) => new URL(c.url).pathname)).toContain("/apis/extensions/v1beta1");
    expect(calls.find((c) => c.method === "PATCH")?.url).toContain("/apis/extensions/v1beta1/namespaces/shop/ingresses/web");
  });

  it("errors, without writing, when the group does not serve the kind", async () => {
    const calls = stubFetch({ "/apis/example.com/v1": widgets });
    await expect(
      new OpenShiftClient(config().connection).apply({ apiVersion: "example.com/v1", kind: "Gadget", metadata: { name: "g", namespace: "shop" } }, false),
    ).rejects.toThrow(/Kind 'Gadget' is not served by example.com\/v1/);
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  });

  it("applies the namespace policy to a discovered custom resource", async () => {
    stubFetch({ "/apis/example.com/v1": widgets });
    const b = stubBackend();
    const res = await (await connect()).callTool({
      name: "apply_resource",
      arguments: { manifest: { apiVersion: "example.com/v1", kind: "Widget", metadata: { name: "w1", namespace: "kube-system" } } },
    });
    expect(text(res)).toMatch(/protected/);
    expect(b.apply).not.toHaveBeenCalled();
  });
});
