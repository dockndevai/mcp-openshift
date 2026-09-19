import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AppConfig } from "./config.js";
import { makeConfirmer } from "./elicit.js";
import { AuthError } from "./openshift/auth.js";
import { OpenShiftClient, OpenShiftError } from "./openshift/client.js";
import { PolicyError, SecurityPolicy } from "./security.js";
import { adminTools } from "./tools/admin.js";
import { annotationsFor } from "./tools/annotations.js";
import { readTools } from "./tools/read.js";
import type { ToolContext, ToolDef } from "./tools/types.js";
import { writeTools } from "./tools/write.js";

export const ALL_TOOLS: ToolDef[] = [...readTools, ...writeTools, ...adminTools];

export function buildServer(config: AppConfig): { server: McpServer; client: OpenShiftClient; enabled: string[] } {
  const policy = new SecurityPolicy(config.security);
  const client = new OpenShiftClient(config.connection);

  const server = new McpServer({ name: "openshift", version: "0.1.0" });
  const ctx: ToolContext = { client, policy, confirm: makeConfirmer(server) };

  const enabled: string[] = [];
  for (const tool of ALL_TOOLS) {
    if (!policy.isCapabilityEnabled(tool.capability)) continue;
    enabled.push(tool.name);
    server.registerTool(
      tool.name,
      { ...tool.config, annotations: annotationsFor(tool) },
      async (args: Record<string, unknown>) => {
        try {
          return await tool.handler(args ?? {}, ctx);
        } catch (err) {
          return toErrorResult(err);
        }
      },
    );
  }

  return { server, client, enabled };
}

function toErrorResult(err: unknown) {
  let message: string;
  if (err instanceof PolicyError) {
    message = `Policy denied: ${err.message}`;
  } else if (err instanceof AuthError) {
    message = `Authentication failed: ${err.message}`;
  } else if (err instanceof OpenShiftError) {
    message =
      err.status === 401 || err.status === 403
        ? `The cluster refused this request (${err.status}): ${err.message}. Your account's RBAC may not permit it.`
        : `Cluster error (${err.status}): ${err.message}`;
  } else if (err instanceof Error) {
    message = `${err.name}: ${err.message}`;
  } else {
    message = String(err);
  }
  return { content: [{ type: "text" as const, text: message }], isError: true };
}
