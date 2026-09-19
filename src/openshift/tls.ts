/**
 * TLS dispatcher for talking to a cluster whose API/OAuth servers use a private CA.
 *
 * OpenShift clusters are almost always fronted by a custom CA (or a self-signed dev cert). Node's
 * global `fetch` verifies against the system trust store by default, so we build an undici `Agent`
 * that either trusts the supplied CA bundle or (development only) skips verification, and pass it as
 * the `dispatcher` on every request.
 */
import { readFileSync } from "node:fs";
import { Agent } from "undici";

export function makeDispatcher(caCertPath?: string, insecure?: boolean): Agent | undefined {
  if (!caCertPath && !insecure) return undefined;
  const connect: { rejectUnauthorized?: boolean; ca?: string } = {};
  if (insecure) connect.rejectUnauthorized = false;
  if (caCertPath) connect.ca = readFileSync(caCertPath, "utf8");
  return new Agent({ connect });
}
