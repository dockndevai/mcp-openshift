/**
 * Cluster token acquisition.
 *
 * A `TokenProvider` hands the HTTP client a valid bearer token on demand. Two implementations:
 *
 *   - **StaticTokenProvider** — returns OPENSHIFT_TOKEN verbatim.
 *   - **PasswordProvider** — the OAuth *request-token* flow that `oc login -u … -p …` uses. It
 *     discovers the cluster's OAuth server, then does a single GET to the authorize endpoint with
 *     HTTP Basic credentials and `response_type=token`; the server answers with a 302 whose Location
 *     fragment carries `#access_token=…`. The token (and its expiry) are cached to disk (0600) and
 *     reused until shortly before expiry; a 401 from the API server forces a fresh login.
 *
 * The password is sent only to the cluster's own OAuth endpoint over TLS. It is never logged and
 * never written to disk — only the resulting token is cached.
 */
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { request } from "undici";
import type { Connection } from "../config.js";
import { makeDispatcher } from "./tls.js";

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

export interface TokenProvider {
  getToken(): Promise<string>;
  /** Drop any cached token so the next getToken() re-authenticates (called after a 401). */
  invalidate(): void;
}

interface CachedToken {
  accessToken: string;
  /** Epoch ms when the token expires (0 = unknown). */
  expiresAt: number;
}

const EXPIRY_SKEW_MS = 60_000;

class StaticTokenProvider implements TokenProvider {
  constructor(private readonly token: string) {}
  async getToken(): Promise<string> {
    return this.token;
  }
  invalidate(): void {
    /* a static token can't be refreshed */
  }
}

class PasswordProvider implements TokenProvider {
  private mem?: CachedToken;
  private inflight?: Promise<string>;
  private readonly dispatcher: ReturnType<typeof makeDispatcher>;

  constructor(private readonly conn: Connection) {
    this.dispatcher = makeDispatcher(conn.caCertPath, conn.insecureTLS);
  }

  async getToken(): Promise<string> {
    const cached = this.mem ?? this.load();
    if (cached && (cached.expiresAt === 0 || cached.expiresAt - EXPIRY_SKEW_MS > Date.now())) {
      this.mem = cached;
      return cached.accessToken;
    }
    if (this.inflight) return this.inflight;
    this.inflight = this.login().finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  invalidate(): void {
    this.mem = undefined;
  }

  /** Discover the OAuth authorize endpoint from the API server's well-known metadata. */
  private async authorizeEndpoint(): Promise<string> {
    const url = `${this.conn.server}/.well-known/oauth-authorization-server`;
    const res = await request(url, { method: "GET", dispatcher: this.dispatcher, headers: { accept: "application/json" } });
    if (res.statusCode >= 400) {
      throw new AuthError(
        `Could not read the cluster's OAuth metadata (${res.statusCode}) at ${url}. Check OPENSHIFT_SERVER and TLS settings.`,
      );
    }
    const body = (await res.body.json()) as { authorization_endpoint?: string };
    if (!body.authorization_endpoint) throw new AuthError("OAuth metadata did not include an authorization_endpoint.");
    return body.authorization_endpoint;
  }

  private async login(): Promise<string> {
    const auth = this.conn.auth;
    const authorize = await this.authorizeEndpoint();
    const url =
      `${authorize}?client_id=${encodeURIComponent(auth.oauthClientId)}&response_type=token` +
      `&redirect_uri=${encodeURIComponent(`${this.conn.server}/oauth/token/implicit`)}`;
    const basic = Buffer.from(`${auth.username}:${auth.password ?? ""}`).toString("base64");

    // undici's request() does not follow redirects, so the 302's Location header is ours to read.
    const res = await request(url, {
      method: "GET",
      dispatcher: this.dispatcher,
      headers: { authorization: `Basic ${basic}`, "x-csrf-token": "1", accept: "application/json" },
    });
    // Drain the body so the socket is released.
    await res.body.text().catch(() => "");

    const location = res.headers["location"];
    const loc = Array.isArray(location) ? location[0] : location;
    if (res.statusCode === 401) {
      throw new AuthError("Login failed (401): the identity provider rejected the username/password.");
    }
    if (!loc || (res.statusCode !== 302 && res.statusCode !== 303)) {
      throw new AuthError(
        `Login did not return a token (status ${res.statusCode}). The identity provider may not support ` +
          `direct username/password login; obtain a token from the web console and set OPENSHIFT_TOKEN instead.`,
      );
    }
    const frag = loc.split("#")[1] ?? "";
    const params = new URLSearchParams(frag);
    const token = params.get("access_token");
    if (!token) {
      if (/error=/.test(loc)) throw new AuthError(`Login failed: ${new URLSearchParams(frag).get("error_description") ?? loc}`);
      throw new AuthError("Login response did not contain an access_token.");
    }
    const expiresIn = Number(params.get("expires_in") ?? 0);
    const cached: CachedToken = { accessToken: token, expiresAt: expiresIn > 0 ? Date.now() + expiresIn * 1000 : 0 };
    this.mem = cached;
    this.save(cached);
    return token;
  }

  private load(): CachedToken | undefined {
    try {
      const parsed = JSON.parse(readFileSync(this.conn.auth.tokenCachePath, "utf8")) as CachedToken;
      if (parsed && typeof parsed.accessToken === "string") return parsed;
    } catch {
      /* no cache yet */
    }
    return undefined;
  }

  private save(cached: CachedToken): void {
    try {
      mkdirSync(dirname(this.conn.auth.tokenCachePath), { recursive: true, mode: 0o700 });
      writeFileSync(this.conn.auth.tokenCachePath, JSON.stringify(cached), { mode: 0o600 });
      chmodSync(this.conn.auth.tokenCachePath, 0o600);
    } catch (e) {
      process.stderr.write(
        `[mcp-openshift] Warning: could not write token cache: ${e instanceof Error ? e.message : String(e)}\n`,
      );
    }
  }
}

export function createTokenProvider(conn: Connection): TokenProvider {
  if (conn.auth.mode === "token") {
    if (!conn.auth.token) throw new AuthError("OPENSHIFT_TOKEN is not set.");
    return new StaticTokenProvider(conn.auth.token);
  }
  if (!conn.auth.username || conn.auth.password === undefined) {
    throw new AuthError("Password auth needs OPENSHIFT_USERNAME and OPENSHIFT_PASSWORD.");
  }
  return new PasswordProvider(conn);
}
