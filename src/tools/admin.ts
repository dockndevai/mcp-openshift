import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

/**
 * Admin tools. Registered only in `admin` mode, gated behind OPENSHIFT_ALLOW_DELETE=true, plus a
 * human confirmation via elicitation. Refused for protected namespaces. Deleting a Kubernetes
 * resource is not recoverable through the API, so this is deliberately hard to reach.
 */
export const adminTools: ToolDef[] = [
  {
    name: "delete_resource",
    capability: "admin",
    destructive: true,
    config: {
      title: "Delete a resource",
      description:
        "Delete a resource by kind + name (+ namespace). Not recoverable. Requires admin mode and " +
        "OPENSHIFT_ALLOW_DELETE=true, refuses protected namespaces, and prompts for human confirmation. " +
        "Honours OPENSHIFT_DRY_RUN.",
      inputSchema: {
        kind: z.string().describe("Resource kind (e.g. pod, deployment, route, configmap)."),
        name: z.string().min(1).describe("Resource name."),
        namespace: z.string().optional().describe("Namespace / project (omit for cluster-scoped kinds)."),
      },
    },
    handler: async (args, { client, policy, confirm, guard }) => {
      const kind = args.kind as string;
      const name = args.name as string;
      const ns = args.namespace as string | undefined;
      const { dryRun } = policy.guard({ tool: "delete_resource", capability: "admin", destructive: true, namespace: ns });
      const target = `${kind}/${name}${ns ? ` in ${ns}` : ""}`;
      if (dryRun) return textResult(`[dry-run] Would delete ${target}.`);
      await guard.enforce(
        { tool: "delete_resource", command: `kubectl delete ${kind}/${name} -n ${ns ?? "default"}`, context: target },
        confirm,
      );
      // Deleting a namespace / project removes everything in it: the one delete that also asks the human to type the name.
      const normalized = kind.toLowerCase().replace(/s$/, "");
      const isNamespace = normalized === "namespace" || normalized === "project";
      const ok = await confirm.confirm({
        action: isNamespace ? `delete ${normalized} (and everything in it)` : "delete resource",
        target: isNamespace ? name : target,
        typed: isNamespace,
        // uid@resourceVersion of the exact object. Limit: any write (including status updates) changes
        // resourceVersion, which fails closed; a recreate under the same name changes the uid.
        probe: () => client.resourceVersion(kind, name, ns),
      });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      // The pinned token is also sent as delete preconditions, so the API server rejects a stale delete.
      return jsonResult(await client.deleteResource(kind, name, ns, false, ok.receipt.version));
    },
  },
];
