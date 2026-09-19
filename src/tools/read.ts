import { z } from "zod";
import type { ToolDef } from "./types.js";
import { jsonResult, textResult } from "./types.js";

const kind = z
  .string()
  .describe(
    "Resource kind — e.g. pod, deployment, deploymentconfig, service, route, configmap, secret, " +
      "build, buildconfig, imagestream, statefulset, daemonset, job, cronjob, pvc, node, project. " +
      "Singular or plural accepted.",
  );
const namespace = z.string().optional().describe("Namespace / project. Required for namespaced kinds; omit for cluster-scoped.");

export const readTools: ToolDef[] = [
  {
    name: "whoami",
    capability: "read",
    config: {
      title: "Who am I",
      description: "Return the authenticated user (name and groups) — confirm which identity the server is using.",
      inputSchema: {},
    },
    handler: async (_a, { client, policy }) => {
      policy.guard({ tool: "whoami", capability: "read" });
      return jsonResult(await client.whoami());
    },
  },
  {
    name: "list_projects",
    capability: "read",
    config: {
      title: "List projects",
      description:
        "List the projects (namespaces) you can see, with name, display name and phase. Start here to find a " +
        "namespace to work in.",
      inputSchema: {},
    },
    handler: async (_a, { client, policy }) => {
      policy.guard({ tool: "list_projects", capability: "read" });
      return jsonResult(await client.listProjects());
    },
  },
  {
    name: "list_resources",
    capability: "read",
    config: {
      title: "List resources",
      description:
        "List resources of a kind, optionally in a namespace and filtered by a label selector. Returns the raw " +
        "Kubernetes/OpenShift list (secret values are redacted). Works for core and OpenShift kinds " +
        "(pods, deployments, deploymentconfigs, routes, services, builds, imagestreams, …).",
      inputSchema: {
        kind,
        namespace,
        label_selector: z.string().optional().describe("Label selector, e.g. app=web,tier!=cache"),
        limit: z.number().int().min(1).max(500).optional().describe("Max items (capped by OPENSHIFT_MAX_RESULTS)"),
      },
    },
    handler: async (a, { client, policy }) => {
      policy.guard({ tool: "list_resources", capability: "read", namespace: a.namespace as string | undefined });
      return jsonResult(
        await client.listByKind(a.kind as string, a.namespace as string | undefined, {
          labelSelector: a.label_selector as string | undefined,
          limit: a.limit as number | undefined,
        }),
      );
    },
  },
  {
    name: "get_resource",
    capability: "read",
    config: {
      title: "Get a resource",
      description:
        "Fetch a single resource by kind + name (+ namespace for namespaced kinds), with its full spec/status. " +
        "Secret values are redacted.",
      inputSchema: { kind, name: z.string().describe("Resource name"), namespace },
    },
    handler: async (a, { client, policy }) => {
      policy.guard({ tool: "get_resource", capability: "read", namespace: a.namespace as string | undefined });
      return jsonResult(await client.getByKind(a.kind as string, a.name as string, a.namespace as string | undefined));
    },
  },
  {
    name: "pod_logs",
    capability: "read",
    config: {
      title: "Pod logs",
      description: "Read a pod's container logs (most recent lines). Optionally a specific container or the previous instance.",
      inputSchema: {
        namespace: z.string().describe("Namespace / project the pod is in"),
        name: z.string().describe("Pod name (from list_resources kind=pod)"),
        container: z.string().optional().describe("Container name (defaults to the first / only container)"),
        tail_lines: z.number().int().min(1).max(5000).optional().describe("How many trailing lines to return (default 200)"),
        previous: z.boolean().optional().describe("Read the previous (crashed) container instance's logs"),
      },
    },
    handler: async (a, { client, policy }) => {
      policy.guard({ tool: "pod_logs", capability: "read", namespace: a.namespace as string });
      const logs = await client.podLogs(a.namespace as string, a.name as string, {
        container: a.container as string | undefined,
        tailLines: a.tail_lines as number | undefined,
        previous: a.previous as boolean | undefined,
      });
      return textResult(logs || "(no log output)");
    },
  },
  {
    name: "list_events",
    capability: "read",
    config: {
      title: "List events",
      description: "List recent events in a namespace — the fastest way to see why something is failing to schedule/start.",
      inputSchema: {
        namespace: z.string().describe("Namespace / project"),
        limit: z.number().int().min(1).max(500).optional().describe("Max events (capped by OPENSHIFT_MAX_RESULTS)"),
      },
    },
    handler: async (a, { client, policy }) => {
      policy.guard({ tool: "list_events", capability: "read", namespace: a.namespace as string });
      return jsonResult(await client.listByKind("event", a.namespace as string, { limit: a.limit as number | undefined }));
    },
  },
];
