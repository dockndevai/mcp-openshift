import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { AppConfig } from "../src/config.js";
import { OpenShiftClient, parseVersionToken, versionToken } from "../src/openshift/client.js";
import { buildServer } from "../src/server.js";

const config = (requireHumanApproval = false): AppConfig => ({
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
    protectedNamespaces: ["kube-system"],
    allowApply: true,
    allowDelete: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval,
  },
});

type Answer = { action: "accept" | "decline"; content?: Record<string, unknown> };

/** Connect an in-memory MCP client (optionally able to answer elicitation) to a freshly built server. */
async function connect(opts: { requireHuman?: boolean; answer?: (message: string) => Answer | Promise<Answer>; elicits?: boolean }) {
  const { server } = buildServer(config(opts.requireHuman));
  const prompts: string[] = [];
  const client = new Client({ name: "t", version: "0" }, { capabilities: opts.elicits === false ? {} : { elicitation: {} } });
  if (opts.elicits !== false) {
    client.setRequestHandler(ElicitRequestSchema, async (req) => {
      prompts.push(req.params.message);
      return (await opts.answer?.(req.params.message)) ?? { action: "accept", content: { confirm: true, typed: "shop" } };
    });
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return { client, prompts };
}

const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");

const delPod = { kind: "pod", name: "web-0", namespace: "shop" };
const delNs = { kind: "namespace", name: "shop" };

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("version tokens", () => {
  it("round-trips uid@resourceVersion and rejects incomplete objects", () => {
    expect(versionToken({ metadata: { uid: "u-1", resourceVersion: "42" } })).toBe("u-1@42");
    expect(versionToken({ metadata: { uid: "u-1" } })).toBeUndefined();
    expect(versionToken(undefined)).toBeUndefined();
    expect(parseVersionToken("u-1@42")).toEqual({ uid: "u-1", resourceVersion: "42" });
    expect(parseVersionToken("garbage")).toBeUndefined();
    expect(parseVersionToken(undefined)).toBeUndefined();
  });
});

describe("delete_resource approval (end to end)", () => {
  it("shows the tool, full arguments, version and fingerprint, then deletes with the pinned token", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({ status: "Success" });
    const { client, prompts } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("Success");
    expect(del).toHaveBeenCalledWith("pod", "web-0", "shop", false, "u-1@100");
    expect(prompts[0]).toContain("tool: delete_resource");
    expect(prompts[0]).toContain('{"kind":"pod","name":"web-0","namespace":"shop"}');
    expect(prompts[0]).toContain("resource version: u-1@100");
    expect(prompts[0]).toMatch(/fingerprint: [0-9a-f]{16}/);
  });

  it("does NOT delete when the object changed while the human was deciding", async () => {
    const versions = ["u-1@100", "u-1@101"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the object was recreated (new uid) while the human was deciding", async () => {
    const versions = ["u-1@100", "u-2@100"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the human declines", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({ answer: () => ({ action: "decline" }) });
    await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(del).not.toHaveBeenCalled();
  });

  it("does not ask for a typed name for an ordinary delete", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({ status: "Success" });
    // Answers with the checkbox only: an ordinary delete must not require the typed field.
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true } }) });
    await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(del).toHaveBeenCalledTimes(1);
  });
});

describe("namespace / project deletion requires the typed name", () => {
  it("deletes when the human types the namespace name", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("ns-1@7");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({ status: "Success" });
    const { client, prompts } = await connect({});
    await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(prompts[0]).toContain('delete namespace (and everything in it): "shop"');
    expect(del).toHaveBeenCalledWith("namespace", "shop", undefined, false, "ns-1@7");
  });

  it("treats a project the same way", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("ns-1@7");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true, typed: "wrong" } }) });
    const res = await client.callTool({ name: "delete_resource", arguments: { kind: "project", name: "shop" } });
    expect(text(res)).toContain("typed confirmation did not match");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the typed name does not match", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("ns-1@7");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({ answer: () => ({ action: "accept", content: { confirm: true, typed: "wrong" } }) });
    const res = await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(text(res)).toContain("typed confirmation did not match");
    expect(del).not.toHaveBeenCalled();
  });

  it("does NOT delete when the namespace changed while the human was deciding", async () => {
    const versions = ["ns-1@7", "ns-1@8"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "delete_resource", arguments: delNs });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(del).not.toHaveBeenCalled();
  });
});

describe("OPENSHIFT_REQUIRE_HUMAN_APPROVAL", () => {
  it("falls back to the flags when the client cannot elicit (default)", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client } = await connect({ elicits: false });
    await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(del).toHaveBeenCalledWith("pod", "web-0", "shop", false, "u-1@100");
  });

  it("refuses to delete when the client cannot elicit and human approval is required", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue("u-1@100");
    const del = vi.spyOn(OpenShiftClient.prototype, "deleteResource").mockResolvedValue({});
    const { client, prompts } = await connect({ elicits: false, requireHuman: true });
    const res = await client.callTool({ name: "delete_resource", arguments: delPod });
    expect(text(res)).toContain("no human approval channel");
    expect(del).not.toHaveBeenCalled();
    expect(prompts).toHaveLength(0);
  });

  it("refuses apply_resource when the client cannot elicit and human approval is required", async () => {
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockResolvedValue(undefined);
    const apply = vi.spyOn(OpenShiftClient.prototype, "apply").mockResolvedValue({});
    const { client } = await connect({ elicits: false, requireHuman: true });
    const res = await client.callTool({
      name: "apply_resource",
      arguments: { manifest: { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "shop" } } },
    });
    expect(text(res)).toContain("no human approval channel");
    expect(apply).not.toHaveBeenCalled();
  });
});

describe("other bound approvals", () => {
  const manifest = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg", namespace: "shop" }, data: { a: "1" } };

  it("apply_resource refuses when the live object changed during the prompt", async () => {
    const versions = ["c-1@10", "c-1@11"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const apply = vi.spyOn(OpenShiftClient.prototype, "apply").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "apply_resource", arguments: { manifest } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(apply).not.toHaveBeenCalled();
  });

  it("apply_resource refuses when an object that did not exist appeared during the prompt", async () => {
    const versions: Array<string | undefined> = [undefined, "c-9@1"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const apply = vi.spyOn(OpenShiftClient.prototype, "apply").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "apply_resource", arguments: { manifest } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(apply).not.toHaveBeenCalled();
  });

  it("scale to 0 refuses when the workload changed during the prompt", async () => {
    const versions = ["d-1@3", "d-1@4"];
    vi.spyOn(OpenShiftClient.prototype, "resourceVersion").mockImplementation(async () => versions.shift());
    const scale = vi.spyOn(OpenShiftClient.prototype, "scale").mockResolvedValue({});
    const { client } = await connect({});
    const res = await client.callTool({ name: "scale", arguments: { namespace: "shop", name: "web", replicas: 0 } });
    expect(text(res)).toContain("resource changed since the prompt");
    expect(scale).not.toHaveBeenCalled();
  });
});

describe("OpenShiftClient native concurrency", () => {
  const conn = config().connection;
  const mockFetch = (status: number, body: unknown) => {
    const f = vi.fn(async () => new Response(JSON.stringify(body), { status }));
    vi.stubGlobal("fetch", f);
    return f;
  };

  it("sends the approved uid + resourceVersion as DeleteOptions preconditions", async () => {
    const f = mockFetch(200, { status: "Success" });
    await new OpenShiftClient(conn).deleteResource("pod", "web-0", "shop", false, "u-1@100");
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.test:6443/api/v1/namespaces/shop/pods/web-0");
    expect(init.method).toBe("DELETE");
    expect(JSON.parse(init.body as string)).toEqual({
      apiVersion: "v1",
      kind: "DeleteOptions",
      preconditions: { uid: "u-1", resourceVersion: "100" },
    });
  });

  it("sends no body when the approval was not bound to a version", async () => {
    const f = mockFetch(200, { status: "Success" });
    await new OpenShiftClient(conn).deleteResource("pod", "web-0", "shop", false);
    const [, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.body).toBeUndefined();
  });

  it("resourceVersion is uid@resourceVersion, undefined on 404, and throws on other errors", async () => {
    const c = new OpenShiftClient(conn);
    mockFetch(200, { kind: "Pod", metadata: { uid: "u-9", resourceVersion: "3" } });
    expect(await c.resourceVersion("pod", "p", "ns")).toBe("u-9@3");
    mockFetch(404, { message: "not found" });
    expect(await c.resourceVersion("pod", "p", "ns")).toBeUndefined();
    mockFetch(403, { message: "forbidden" });
    await expect(c.resourceVersion("pod", "p", "ns")).rejects.toMatchObject({ status: 403 });
  });
});
