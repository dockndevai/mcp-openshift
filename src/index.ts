#!/usr/bin/env node
/**
 * MCP server for OpenShift / Kubernetes.
 *
 * Lets an agent explore and operate an OpenShift cluster — projects, pods and logs, deployments and
 * deploymentconfigs, routes, services, builds, imagestreams and any other resource by kind — and,
 * in higher modes, scale workloads, restart deployments, apply manifests, and delete.
 *
 * Auth: a bearer token (OPENSHIFT_TOKEN, e.g. from the web console's "Copy login command"), or
 * username/password against the cluster's local identity provider (OPENSHIFT_USERNAME/PASSWORD),
 * which performs the same OAuth request-token flow `oc login -u -p` uses. See src/openshift/auth.ts.
 *
 * Safe by default: starts read-only, so only the read tools are registered. Writes need
 * OPENSHIFT_MODE=read-write; creating/updating resources additionally needs OPENSHIFT_ALLOW_APPLY;
 * deletes need admin mode plus OPENSHIFT_ALLOW_DELETE. System namespaces are protected, and the
 * access model (src/security.ts) is defence in depth over the cluster's own RBAC.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { hasCredentials, loadConfig, missingHint } from "./config.js";
import { buildServer } from "./server.js";

const config = loadConfig();

if (!hasCredentials(config.connection)) {
  process.stderr.write(`mcp-openshift: incomplete configuration. ${missingHint(config.connection)}\n`);
  process.exit(1);
}

const { server, enabled } = buildServer(config);

const transport = new StdioServerTransport();
await server.connect(transport);
// stdout carries the protocol; diagnostics go to stderr.
process.stderr.write(
  `openshift-mcp connected [server=${config.connection.server}, auth=${config.connection.auth.mode}, ` +
    `mode=${config.security.mode}${config.connection.insecureTLS ? ", INSECURE-TLS" : ""}, ` +
    `tools=${enabled.length}: ${enabled.join(", ")}]\n`,
);
