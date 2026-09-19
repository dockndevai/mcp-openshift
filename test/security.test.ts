import { describe, expect, it } from "vitest";
import { PolicyError, SecurityPolicy, type SecurityConfig } from "../src/security.js";

function makePolicy(overrides: Partial<SecurityConfig> = {}): SecurityPolicy {
  return new SecurityPolicy({
    mode: "read-only",
    namespaceAllowlist: [],
    protectedNamespaces: ["kube-system", "openshift", "openshift-*"],
    allowApply: false,
    allowDelete: false,
    dryRun: false,
    auditLog: false,
    ...overrides,
  });
}

describe("capability gating", () => {
  it("read-only enables read only", () => {
    const p = makePolicy();
    expect(p.isCapabilityEnabled("read")).toBe(true);
    expect(p.isCapabilityEnabled("write")).toBe(false);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });
  it("read-write enables read and write but not admin", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(p.isCapabilityEnabled("write")).toBe(true);
    expect(p.isCapabilityEnabled("admin")).toBe(false);
  });
});

describe("mode vs capability at guard time", () => {
  it("rejects a write in read-only mode", () => {
    const p = makePolicy();
    expect(() => p.guard({ tool: "scale", capability: "write" })).toThrow(PolicyError);
  });
  it("rejects admin in read-write mode", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(() => p.guard({ tool: "delete_resource", capability: "admin", destructive: true })).toThrow(/admin/);
  });
});

describe("namespace allowlist + protection", () => {
  it("blocks writes to namespaces outside a non-empty allowlist", () => {
    const p = makePolicy({ mode: "read-write", namespaceAllowlist: ["team-a"] });
    expect(() => p.guard({ tool: "scale", capability: "write", namespace: "team-b" })).toThrow(/allowlist/);
  });
  it("allows reading a protected namespace but not writing to it", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(() => p.guard({ tool: "list_resources", capability: "read", namespace: "kube-system" })).not.toThrow();
    expect(() => p.guard({ tool: "scale", capability: "write", namespace: "kube-system" })).toThrow(/protected/);
  });
  it("protects wildcard namespace patterns (openshift-*)", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(() => p.guard({ tool: "scale", capability: "write", namespace: "openshift-monitoring" })).toThrow(/protected/);
  });
});

describe("apply gating", () => {
  it("blocks apply without allowApply even in read-write mode", () => {
    const p = makePolicy({ mode: "read-write" });
    expect(() => p.guard({ tool: "apply_resource", capability: "write", requiresApply: true })).toThrow(/ALLOW_APPLY/);
  });
  it("permits apply with allowApply", () => {
    const p = makePolicy({ mode: "read-write", allowApply: true });
    expect(() => p.guard({ tool: "apply_resource", capability: "write", requiresApply: true })).not.toThrow();
  });
});

describe("delete gating", () => {
  it("blocks delete without allowDelete even in admin mode", () => {
    const p = makePolicy({ mode: "admin" });
    expect(() => p.guard({ tool: "delete_resource", capability: "admin", destructive: true })).toThrow(/ALLOW_DELETE/);
  });
  it("permits delete with allowDelete", () => {
    const p = makePolicy({ mode: "admin", allowDelete: true });
    expect(() => p.guard({ tool: "delete_resource", capability: "admin", destructive: true })).not.toThrow();
  });
});

describe("dry run", () => {
  it("flags writes but not reads", () => {
    const p = makePolicy({ mode: "read-write", dryRun: true });
    expect(p.guard({ tool: "get_resource", capability: "read" }).dryRun).toBe(false);
    expect(p.guard({ tool: "scale", capability: "write" }).dryRun).toBe(true);
  });
});
