/**
 * Security policy engine.
 *
 * Flags decide which tools are registered (capability vs. access mode) and whether each call is
 * allowed at runtime (namespace scoping, protected namespaces, apply/delete gating, dry-run). Pure
 * logic — fully unit-testable. Defence in depth on top of what the cluster's RBAC already permits
 * for the authenticated user.
 */

export type Capability = "read" | "write" | "admin";
export type AccessMode = "read-only" | "read-write" | "admin";

const MODE_RANK: Record<AccessMode, number> = { "read-only": 0, "read-write": 1, admin: 2 };
const CAPABILITY_RANK: Record<Capability, number> = { read: 0, write: 1, admin: 2 };

export interface SecurityConfig {
  mode: AccessMode;
  /** If set, only these namespaces may be written to / deleted from. Empty = all (RBAC still applies). */
  namespaceAllowlist: string[];
  /** Namespaces that may be read but never mutated (system / cluster namespaces). Lowercased. */
  protectedNamespaces: string[];
  /** Creating or updating resources (server-side apply) requires this, on top of read-write mode. */
  allowApply: boolean;
  /** Deleting resources requires this, on top of admin mode. */
  allowDelete: boolean;
  /** Validate + log writes against the cluster without persisting (Kubernetes dryRun=All). */
  dryRun: boolean;
  auditLog: boolean;
}

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface GuardContext {
  tool: string;
  capability: Capability;
  /** Namespace a call targets, when it names one. */
  namespace?: string;
  /** Marks a create/update (server-side apply). */
  requiresApply?: boolean;
  destructive?: boolean;
}

export class SecurityPolicy {
  constructor(private readonly config: SecurityConfig) {}

  get mode(): AccessMode {
    return this.config.mode;
  }

  isCapabilityEnabled(capability: Capability): boolean {
    return CAPABILITY_RANK[capability] <= MODE_RANK[this.config.mode];
  }

  isNamespaceAllowed(ns: string): boolean {
    if (this.config.namespaceAllowlist.length === 0) return true;
    return this.config.namespaceAllowlist.includes(ns);
  }
  isNamespaceProtected(ns: string): boolean {
    const n = ns.toLowerCase();
    return this.config.protectedNamespaces.some((p) => n === p || (p.endsWith("*") && n.startsWith(p.slice(0, -1))));
  }

  guard(ctx: GuardContext): { dryRun: boolean } {
    if (!this.isCapabilityEnabled(ctx.capability)) {
      this.audit(ctx, "DENY", `capability '${ctx.capability}' exceeds mode '${this.config.mode}'`);
      throw new PolicyError(
        `Operation '${ctx.tool}' requires '${ctx.capability}' access but the server runs in '${this.config.mode}' mode. Set OPENSHIFT_MODE to grant it.`,
      );
    }

    if (ctx.namespace !== undefined && ctx.namespace !== "" && ctx.capability !== "read") {
      if (!this.isNamespaceAllowed(ctx.namespace)) {
        this.audit(ctx, "DENY", `namespace '${ctx.namespace}' not in allowlist`);
        throw new PolicyError(
          `Namespace '${ctx.namespace}' is not in the configured allowlist (OPENSHIFT_NAMESPACE_ALLOWLIST).`,
        );
      }
      if (this.isNamespaceProtected(ctx.namespace)) {
        this.audit(ctx, "DENY", `namespace '${ctx.namespace}' is protected`);
        throw new PolicyError(
          `Namespace '${ctx.namespace}' is protected (OPENSHIFT_PROTECTED_NAMESPACES); it can be read but not modified.`,
        );
      }
    }

    if (ctx.requiresApply && !this.config.allowApply) {
      this.audit(ctx, "DENY", "apply not enabled");
      throw new PolicyError(
        `Operation '${ctx.tool}' creates or updates a resource and is disabled. Set OPENSHIFT_ALLOW_APPLY=true to enable it.`,
      );
    }

    if (ctx.destructive && !this.config.allowDelete) {
      this.audit(ctx, "DENY", "delete not enabled");
      throw new PolicyError(
        `Destructive operation '${ctx.tool}' is disabled. Set OPENSHIFT_ALLOW_DELETE=true to enable it.`,
      );
    }

    const dryRun = ctx.capability !== "read" && this.config.dryRun;
    this.audit(ctx, dryRun ? "DRY_RUN" : "ALLOW");
    return { dryRun };
  }

  private audit(ctx: GuardContext, decision: string, reason?: string): void {
    if (!this.config.auditLog) return;
    const line = {
      ts: new Date().toISOString(),
      audit: "openshift-mcp",
      decision,
      tool: ctx.tool,
      capability: ctx.capability,
      namespace: ctx.namespace ?? null,
      requiresApply: ctx.requiresApply ?? false,
      destructive: ctx.destructive ?? false,
      ...(reason ? { reason } : {}),
    };
    process.stderr.write(`${JSON.stringify(line)}\n`);
  }
}
