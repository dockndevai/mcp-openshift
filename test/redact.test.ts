import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { AppConfig } from "../src/config.js";
import { OpenShiftClient } from "../src/openshift/client.js";
import { redactSecret } from "../src/redact.js";
import { buildServer } from "../src/server.js";

const config: AppConfig = {
  connection: {
    server: "https://api.test:6443",
    auth: { mode: "token", token: "t", oauthClientId: "c", tokenCachePath: "/dev/null" },
    insecureTLS: false,
    timeoutMs: 1000,
    maxResults: 10,
  },
  security: {
    mode: "admin",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    allowApply: true,
    allowDelete: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
  },
};

async function connect() {
  const { server } = buildServer(config);
  const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

const PASSWORD = "s3cr3t-p4ssw0rd";
const B64 = Buffer.from(PASSWORD).toString("base64");
const LAST = "kubectl.kubernetes.io/last-applied-configuration";
const annotations = () => ({ [LAST]: JSON.stringify({ data: { password: B64 } }), team: "payments" });
const secretBody = (extra: Record<string, unknown> = {}) => ({
  apiVersion: "v1",
  kind: "Secret",
  metadata: { name: "db", namespace: "shop", uid: "u-1", resourceVersion: "7", annotations: annotations() },
  data: { password: B64 },
  stringData: { token: PASSWORD },
  ...extra,
});
/** What the API server really sends for a list: items carry NO kind/apiVersion. */
const secretList = () => ({
  apiVersion: "v1",
  kind: "SecretList",
  items: [
    { metadata: { name: "a", annotations: annotations() }, data: { password: B64 }, type: "Opaque" },
    { metadata: { name: "b" }, data: { password: B64 } },
  ],
});

function stubFetch(body: unknown, status = 200) {
  const calls: Array<{ url: string; method: string }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, method: init?.method ?? "GET" });
      return new Response(JSON.stringify(body), { status });
    }),
  );
  return calls;
}
const leaks = (out: string) => out.includes(PASSWORD) || out.includes(B64);
const REDACTED = `<redacted, ${PASSWORD.length} bytes>`;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("every path that can return a Secret redacts it", () => {
  it("list_resources kind=secret (items have no kind)", async () => {
    stubFetch(secretList());
    const out = text(await (await connect()).callTool({ name: "list_resources", arguments: { kind: "secret", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
    const items = JSON.parse(out).items;
    expect(items[0].data.password).toBe(REDACTED);
    expect(items[0].type).toBe("Opaque");
    expect(items[0].metadata.annotations[LAST]).toBe("<redacted>");
    expect(items[0].metadata.annotations.team).toBe("payments");
  });

  it("list_resources kind=secrets (plural) and a SecretList whose items omit kind", async () => {
    stubFetch(secretList());
    const out = text(await (await connect()).callTool({ name: "list_resources", arguments: { kind: "Secrets", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
  });

  it("list_resources redacts by the requested kind when the list itself omits `kind` too", async () => {
    const { kind: _k, ...noKind } = secretList();
    stubFetch(noKind);
    const out = text(await (await connect()).callTool({ name: "list_resources", arguments: { kind: "secret", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
  });

  it("get_resource kind=secret: data, stringData and the last-applied annotation", async () => {
    stubFetch(secretBody());
    const out = text(await (await connect()).callTool({ name: "get_resource", arguments: { kind: "secret", name: "db", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
    const o = JSON.parse(out);
    expect(Object.keys(o.data)).toEqual(["password"]);
    expect(o.data.password).toBe(REDACTED);
    expect(o.stringData.token).toBe(REDACTED);
    expect(o.metadata.annotations[LAST]).toBe("<redacted>");
    expect(o.metadata.annotations.team).toBe("payments");
  });

  it("get_resource redacts by the requested kind even when the response omits `kind`", async () => {
    const { kind: _k, ...noKind } = secretBody();
    stubFetch(noKind);
    const out = text(await (await connect()).callTool({ name: "get_resource", arguments: { kind: "secret", name: "db", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
  });

  it("delete_resource (the API returns the deleted object)", async () => {
    stubFetch(secretBody());
    const out = text(await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "secret", name: "db", namespace: "shop" } }));
    expect(out).toContain("db");
    expect(leaks(out)).toBe(false);
  });

  it("scale (the response of the targeted subresource), with or without `kind` in it", async () => {
    const { kind: _k, ...noKind } = secretBody();
    for (const body of [secretBody(), noKind]) {
      stubFetch(body);
      const out = JSON.stringify(await new OpenShiftClient(config.connection).scale("secret", "shop", "db", 1, false));
      expect(leaks(out)).toBe(false);
    }
  });

  it("delete_resource redacts by the requested kind when the response omits `kind`", async () => {
    const { kind: _k, ...noKind } = secretBody();
    stubFetch(noKind);
    const out = text(await (await connect()).callTool({ name: "delete_resource", arguments: { kind: "secret", name: "db", namespace: "shop" } }));
    expect(leaks(out)).toBe(false);
  });

  it("apply_resource returns only the applied object's identity, never its content (real and dry-run)", async () => {
    stubFetch(secretBody());
    const manifest = { apiVersion: "v1", kind: "Secret", metadata: { name: "db", namespace: "shop" }, stringData: { token: PASSWORD } };
    const c = await connect();
    expect(leaks(text(await c.callTool({ name: "apply_resource", arguments: { manifest } })))).toBe(false);
    const r = await new OpenShiftClient(config.connection).apply(manifest, true);
    expect(JSON.stringify(r)).toBe(JSON.stringify({ kind: "Secret", name: "db", namespace: "shop", resourceVersion: "7" }));
  });

  it("list_events and other kinds are untouched", async () => {
    const cm = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg" }, data: { color: "blue" } };
    stubFetch(cm);
    expect(JSON.parse(text(await (await connect()).callTool({ name: "get_resource", arguments: { kind: "configmap", name: "cfg", namespace: "shop" } })))).toEqual(cm);
  });
});

describe("redactSecret", () => {
  it("does not mutate its input", () => {
    const s = secretBody();
    const copy = JSON.parse(JSON.stringify(s));
    redactSecret(s);
    expect(s).toEqual(copy);
  });

  it("recognises a SecretList on its own, and leaves a typed list of other kinds alone", () => {
    expect(leaks(JSON.stringify(redactSecret(secretList())))).toBe(false);
    const pods = { kind: "PodList", items: [{ metadata: { name: "p" }, data: { a: "b" } }] };
    expect(redactSecret(pods)).toEqual(pods);
  });

  it("handles a mixed List by each item's own kind, and a Secret with no data", () => {
    const out = redactSecret({ kind: "List", items: [secretBody(), { kind: "ConfigMap", data: { a: "b" } }] }) as { items: Array<Record<string, any>> };
    expect(leaks(JSON.stringify(out))).toBe(false);
    expect(out.items[1]?.data).toEqual({ a: "b" });
    expect(redactSecret({ kind: "Secret", metadata: { name: "e" } })).toEqual({ kind: "Secret", metadata: { name: "e" } });
  });
});
