import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

/**
 * Write tools. Registered in `read-write` mode and up. `scale`/`rollout_restart` are reversible;
 * `apply_resource` creates or updates and is additionally gated by OPENSHIFT_ALLOW_APPLY plus a
 * human confirmation. All honour the namespace allowlist / protected namespaces and OPENSHIFT_DRY_RUN.
 */
export const writeTools: ToolDef[] = [
  {
    name: "scale",
    capability: "write",
    config: {
      title: "Scale a workload",
      description:
        "Set the replica count of a Deployment or DeploymentConfig. Scaling to 0 stops the workload, so that case " +
        "asks for human confirmation.",
      inputSchema: {
        namespace: z.string().describe("Namespace / project"),
        name: z.string().describe("Workload name"),
        replicas: z.number().int().min(0).max(1000).describe("Desired replica count"),
        kind: z.enum(["deployment", "deploymentconfig"]).optional().describe("Workload kind (default deployment)"),
      },
    },
    handler: async (args, { client, policy, confirm }) => {
      const ns = args.namespace as string;
      const name = args.name as string;
      const replicas = args.replicas as number;
      const kind = (args.kind as string) ?? "deployment";
      const { dryRun } = policy.guard({ tool: "scale", capability: "write", namespace: ns });
      if (dryRun) return textResult(`[dry-run] Would scale ${kind}/${name} in ${ns} to ${replicas}.`);
      if (replicas === 0) {
        const ok = await confirm.confirm({ action: `scale ${kind} to 0 (stop it)`, target: `${ns}/${name}` });
        if (!ok.approved) return textResult(`Scale cancelled — ${ok.reason}.`);
      }
      return jsonResult(await client.scale(kind, ns, name, replicas, false));
    },
  },
  {
    name: "rollout_restart",
    capability: "write",
    config: {
      title: "Restart a deployment",
      description: "Trigger a rolling restart of a Deployment (re-creates its pods). Reversible; pods come back on their own.",
      inputSchema: {
        namespace: z.string().describe("Namespace / project"),
        name: z.string().describe("Deployment name"),
      },
    },
    handler: async (args, { client, policy }) => {
      const ns = args.namespace as string;
      const name = args.name as string;
      const { dryRun } = policy.guard({ tool: "rollout_restart", capability: "write", namespace: ns });
      if (dryRun) return textResult(`[dry-run] Would restart deployment/${name} in ${ns}.`);
      await client.rolloutRestart(ns, name, false);
      return textResult(`Restarted deployment/${name} in ${ns}.`);
    },
  },
  {
    name: "apply_resource",
    capability: "write",
    requiresApply: true,
    config: {
      title: "Apply a resource",
      description:
        "Create or update a resource from a manifest (server-side apply). Gated by OPENSHIFT_ALLOW_APPLY=true and a " +
        "human confirmation. The manifest must include apiVersion, kind, and metadata.name (and metadata.namespace " +
        "for namespaced kinds). Honours OPENSHIFT_DRY_RUN (validates without persisting).",
      inputSchema: {
        manifest: z.record(z.string(), z.any()).describe("The full resource manifest (apiVersion, kind, metadata, spec…)."),
      },
    },
    handler: async (args, { client, policy, confirm }) => {
      const manifest = args.manifest as Record<string, unknown>;
      const md = (manifest.metadata ?? {}) as { name?: string; namespace?: string };
      const { dryRun } = policy.guard({
        tool: "apply_resource",
        capability: "write",
        namespace: md.namespace,
        requiresApply: true,
      });
      const target = `${manifest.kind as string}/${md.name ?? "?"}${md.namespace ? ` in ${md.namespace}` : ""}`;
      if (dryRun) return jsonResult(await client.apply(manifest, true));
      const ok = await confirm.confirm({ action: "apply (create/update) resource", target });
      if (!ok.approved) return textResult(`Apply cancelled — ${ok.reason}.`);
      return jsonResult(await client.apply(manifest, false));
    },
  },
];
