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
    handler: async (args, { client, policy, confirm }) => {
      const kind = args.kind as string;
      const name = args.name as string;
      const ns = args.namespace as string | undefined;
      const { dryRun } = policy.guard({ tool: "delete_resource", capability: "admin", destructive: true, namespace: ns });
      const target = `${kind}/${name}${ns ? ` in ${ns}` : ""}`;
      if (dryRun) return textResult(`[dry-run] Would delete ${target}.`);
      const ok = await confirm.confirm({ action: "delete resource", target });
      if (!ok.approved) return textResult(`Deletion cancelled — ${ok.reason}.`);
      return jsonResult(await client.deleteResource(kind, name, ns, false));
    },
  },
];
