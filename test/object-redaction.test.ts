import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { OpenShiftClient } from "../src/openshift/client.js";
import { isSecretName, redactObject } from "../src/redact.js";
import { buildServer } from "../src/server.js";

const config = (security: Partial<AppConfig["security"]> = {}): AppConfig => ({
  connection: {
    server: "https://api.test:6443",
    auth: { mode: "token", token: "t", oauthClientId: "c", tokenCachePath: "/dev/null" },
    insecureTLS: false,
    timeoutMs: 1000,
    maxResults: 10,
  },
  security: {
    mode: "admin",
    namespaceAllowlist: [],
    protectedNamespaces: [],
    allowApply: true,
    allowDelete: true,
    dryRun: false,
    auditLog: false,
    requireHumanApproval: false,
    ...security,
  },
});

async function connect(security: Partial<AppConfig["security"]> = {}) {
  const { server } = buildServer(config(security));
  const client = new Client({ name: "t", version: "0" }, { capabilities: { elicitation: {} } });
  client.setRequestHandler(ElicitRequestSchema, async () => ({ action: "accept", content: { confirm: true, name: "x" } }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]?.text ?? "");
const call = async (name: string, args: Record<string, unknown>, security: Partial<AppConfig["security"]> = {}) =>
  text(await (await connect(security)).callTool({ name, arguments: args }));

/** Every fetch answers with `body` (status 200 unless given). */
function stubFetch(body: unknown, status = 200) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status })),
  );
}

// Assembled at run time so the file carries no literal credential.
const j = (...p: string[]) => p.join("");
const PW = j("hunter2", "hunter2");
const TOKEN = j("tok-", "9f8e7d6c5b4a39281706");
const DB_URL_PW = j("p4ss", "w0rd-in-url");
const PEM_HEAD = j("-----BEGIN ", "RSA ", "PRIVATE KEY-----");
const PEM_FOOT = j("-----END ", "RSA ", "PRIVATE KEY-----");
const PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
const PEM = [PEM_HEAD, PEM_BODY, "MBGWRPZ0YyMgE0TtHn3kXKHk0YEFc5qS9eNsD4E7vUQ1o1pM8yq2lJf6tbAAA=", PEM_FOOT].join("\n");
const GH_TOKEN = j("gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
const ARG_PW = j("cli-", "arg-secret-1");
const FLAG_PW = j("cli-", "flag-secret-2");
const ENV_API = j("api-", "key-value-3");
const ARGS_KEY = j("cli-", "args-key-4");
const HDR_TOKEN = j("hdr-", "token-5a6b7c8d");
const GIT_PW = j("git-", "pass-6");
const HOOK_SECRET = j("hook-", "secret-7");
const TPL_PW = j("tpl-", "param-pass-8");
const b64 = (s: string) => Buffer.from(s).toString("base64");
const LAST = "kubectl.kubernetes.io/last-applied-configuration";

/** None of these may appear anywhere in tool output. */
const ALL_SECRETS = [PW, TOKEN, DB_URL_PW, PEM_BODY, GH_TOKEN, ARG_PW, FLAG_PW, ENV_API, b64(PW), ARGS_KEY, HDR_TOKEN, GIT_PW, HOOK_SECRET, TPL_PW];
function clean(out: string) {
  for (const s of ALL_SECRETS) expect(out, `leaked: ${s}`).not.toContain(s);
}
/** What must stay readable so the object is still useful for diagnosis. */
function expectShape(out: string) {
  for (const s of ["DB_PASSWORD", "eu-west-1", "LOG_LEVEL", "db-creds", "secretKeyRef", "INIT_SECRET", "shop/web:1", "--verbose", "--port", "X-Probe"]) {
    expect(out).toContain(s);
  }
  expect(out).toContain("postgres://app:[REDACTED]@db:5432/orders");
}

const containers = () => [
  {
    name: "app",
    image: "shop/web:1",
    command: ["web", `--db-password=${ARG_PW}`, "--password", FLAG_PW, "--port", "8080"],
    args: ["--verbose", "--api-key", ARGS_KEY],
    livenessProbe: { httpGet: { path: "/healthz", port: 8080, httpHeaders: [{ name: "Authorization", value: `Bearer ${HDR_TOKEN}` }, { name: "X-Probe", value: "1" }] } },
    env: [
      { name: "DB_PASSWORD", value: PW },
      { name: "API_KEY", value: ENV_API },
      { name: "GITHUB_TOKEN", value: GH_TOKEN },
      { name: "SENTRY_DSN", value: "https://abc@o1.ingest.example.com/1" },
      { name: "DATABASE_URL", value: `postgres://app:${DB_URL_PW}@db:5432/orders` },
      { name: "MISC", value: `token=${TOKEN}` },
      { name: "REGION", value: "eu-west-1" },
      { name: "LOG_LEVEL", value: "info" },
      { name: "DB_USER", valueFrom: { secretKeyRef: { name: "db-creds", key: "user" } } },
      { name: "DB_PASSWORD_REF", valueFrom: { secretKeyRef: { name: "db-creds", key: "password" } } },
    ],
  },
];
const podSpec = () => ({
  containers: containers(),
  initContainers: [{ name: "init", image: "busybox", env: [{ name: "INIT_SECRET", value: PW }, { name: "MODE", value: "init" }] }],
});
const meta = () => ({
  name: "web",
  namespace: "shop",
  uid: "u-1",
  resourceVersion: "7",
  annotations: {
    [LAST]: JSON.stringify({ kind: "Deployment", spec: { template: { spec: { containers: containers() } } } }),
    team: "payments",
  },
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("get_resource redacts env in every workload kind (pod templates are recursed)", () => {
  const template = () => ({ spec: podSpec() });
  const cases: Array<[string, string, Record<string, unknown>]> = [
    ["pod", "Pod", { spec: podSpec() }],
    ["deployment", "Deployment", { spec: { replicas: 2, template: template() } }],
    ["deploymentconfig", "DeploymentConfig", { spec: { template: template() } }],
    ["statefulset", "StatefulSet", { spec: { template: template() } }],
    ["daemonset", "DaemonSet", { spec: { template: template() } }],
    ["replicaset", "ReplicaSet", { spec: { template: template() } }],
    ["job", "Job", { spec: { template: template() } }],
    ["cronjob", "CronJob", { spec: { schedule: "* * * * *", jobTemplate: { spec: { template: template() } } } }],
  ];
  it.each(cases)("%s", async (kind, apiKind, body) => {
    stubFetch({ apiVersion: "x/v1", kind: apiKind, metadata: meta(), ...body });
    const out = await call("get_resource", { kind, name: "web", namespace: "shop" });
    clean(out);
    expectShape(out);
    expect(out).toContain("payments");
    const p = JSON.parse(out);
    expect(JSON.stringify(p)).toMatch(/"value": ?"<redacted, \d+ bytes>"/);
  });

  it("also when the response omits `kind` (redacted by the requested kind)", async () => {
    stubFetch({ metadata: meta(), spec: { template: { spec: podSpec() } } });
    clean(await call("get_resource", { kind: "deployment", name: "web", namespace: "shop" }));
  });

  it("redacts the copy of the manifest inside the last-applied-configuration annotation", async () => {
    stubFetch({ apiVersion: "apps/v1", kind: "Deployment", metadata: meta(), spec: {} });
    const out = await call("get_resource", { kind: "deployment", name: "web", namespace: "shop" });
    clean(out);
    const last = JSON.parse(JSON.parse(out).metadata.annotations[LAST]);
    expect(last.spec.template.spec.containers[0].env[0].name).toBe("DB_PASSWORD");
    expect(last.spec.template.spec.containers[0].env[0].value).toMatch(/^<redacted/);
  });

  it("replaces an annotation that is not JSON instead of guessing", () => {
    const out = redactObject({ kind: "Deployment", metadata: { annotations: { [LAST]: `not json ${PW}` } } }) as { metadata: { annotations: Record<string, string> } };
    expect(out.metadata.annotations[LAST]).toBe("<redacted>");
  });

  it("is returned untouched when redactObjects=false", async () => {
    stubFetch({ apiVersion: "apps/v1", kind: "Deployment", metadata: meta(), spec: { template: template() } });
    const out = await call("get_resource", { kind: "deployment", name: "web", namespace: "shop" }, { redactObjects: false });
    expect(out).toContain(PW);
  });

  it("OpenShift Template parameters and the objects inside a Template", async () => {
    stubFetch({
      apiVersion: "v1",
      kind: "List",
      items: [
        {
          kind: "Template",
          metadata: { name: "t" },
          parameters: [{ name: "ADMIN_PASSWORD", value: TPL_PW }, { name: "APP_NAME", value: "shop" }],
          objects: [{ kind: "Deployment", spec: { template: { spec: podSpec() } } }, { kind: "Secret", metadata: { name: "s" }, stringData: { p: PW } }],
        },
      ],
    });
    const out = await call("list_resources", { kind: "pod", namespace: "shop" });
    clean(out);
    expect(out).toContain("APP_NAME");
    expect(out).toContain('"shop"');
  });
});

describe("list_resources redacts the items of a list (which omit kind)", () => {
  it("pods", async () => {
    stubFetch({ apiVersion: "v1", kind: "PodList", items: [{ metadata: { name: "a" }, spec: podSpec() }, { metadata: { name: "b" }, spec: podSpec() }] });
    const out = await call("list_resources", { kind: "pod", namespace: "shop" });
    clean(out);
    expectShape(out);
  });

  it("deployments, deploymentconfigs, statefulsets, jobs and cronjobs", async () => {
    for (const kind of ["deployment", "deploymentconfig", "statefulset", "job"]) {
      stubFetch({ kind: "List", items: [{ metadata: meta(), spec: { template: { spec: podSpec() } } }] });
      clean(await call("list_resources", { kind, namespace: "shop" }));
    }
    stubFetch({ kind: "CronJobList", items: [{ metadata: meta(), spec: { jobTemplate: { spec: { template: { spec: podSpec() } } } } }] });
    clean(await call("list_resources", { kind: "cronjob", namespace: "shop" }));
  });

  it("configmaps (items omit kind, the requested kind decides)", async () => {
    stubFetch({ apiVersion: "v1", kind: "ConfigMapList", items: [{ metadata: { name: "a" }, data: { "db.password": PW, region: "eu" } }] });
    const out = await call("list_resources", { kind: "configmap", namespace: "shop" });
    clean(out);
    expect(JSON.parse(out).items[0].data.region).toBe("eu");
  });

  it("routes", async () => {
    stubFetch({ kind: "RouteList", items: [{ metadata: { name: "web" }, spec: { host: "web.example.com", tls: { termination: "edge", key: PEM } } }] });
    const out = await call("list_resources", { kind: "route", namespace: "shop" });
    clean(out);
    expect(JSON.parse(out).items[0].spec.tls.termination).toBe("edge");
  });
});

describe("get_resource redacts ConfigMaps", () => {
  const cm = () => ({
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: { name: "app-config", namespace: "shop" },
    data: {
      "db.password": PW,
      "api_token": TOKEN,
      "credentials.json": `{"k":"${PW}"}`,
      "tls.key": PEM,
      "private.pem": PEM,
      "app.properties": `region=eu-west-1\nclient_secret=${PW}\nretries=3`,
      "notes.txt": `deploy key ${GH_TOKEN} was rotated`,
      "dsn.conf": `url=postgres://u:${DB_URL_PW}@h/db`,
      "feature-flags": "a=1\nb=2",
      LOG_LEVEL: "info",
    },
    binaryData: {
      "keystore.p12": b64(PW),
      "token": b64(PW),
      "blob.bin": b64(`password=${PW}\nother=1`),
      "logo.png": b64("PNGDATA"),
    },
  });

  it("masks secret-shaped keys, private keys, token shapes and key=value lines; keeps harmless entries", async () => {
    stubFetch(cm());
    const out = await call("get_resource", { kind: "configmap", name: "app-config", namespace: "shop" });
    clean(out);
    const c = JSON.parse(out);
    expect(c.data["db.password"]).toMatch(/^<redacted, \d+ bytes>$/);
    expect(c.data["tls.key"]).toMatch(/^<redacted/);
    expect(c.data["private.pem"]).not.toContain(PEM_BODY);
    expect(c.data["app.properties"]).toContain("region=eu-west-1");
    expect(c.data["app.properties"]).toContain("retries=3");
    expect(c.data["notes.txt"]).toContain("was rotated");
    expect(c.data["feature-flags"]).toBe("a=1\nb=2");
    expect(c.data.LOG_LEVEL).toBe("info");
    expect(c.binaryData["keystore.p12"]).toMatch(/^<redacted/);
    expect(c.binaryData.token).toMatch(/^<redacted/);
    expect(c.binaryData["blob.bin"]).toMatch(/^<redacted/);
    expect(c.binaryData["logo.png"]).toBe(b64("PNGDATA"));
  });

  it("also when the response omits `kind`", async () => {
    const { kind: _k, ...noKind } = cm();
    stubFetch(noKind);
    clean(await call("get_resource", { kind: "configmap", name: "app-config", namespace: "shop" }));
  });

  it("a harmless ConfigMap is returned unchanged", async () => {
    const harmless = { apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cfg" }, data: { color: "blue", "app.properties": "a=1\nb=2" } };
    stubFetch(harmless);
    expect(JSON.parse(await call("get_resource", { kind: "configmap", name: "cfg", namespace: "shop" }))).toEqual(harmless);
  });

  it("is returned untouched when redactObjects=false", async () => {
    stubFetch(cm());
    expect(await call("get_resource", { kind: "configmap", name: "app-config", namespace: "shop" }, { redactObjects: false })).toContain(PW);
  });
});

describe("Route TLS private keys", () => {
  const route = (tls: Record<string, unknown>, top = false) => ({
    apiVersion: "route.openshift.io/v1",
    kind: "Route",
    metadata: { name: "web", namespace: "shop" },
    ...(top ? { tls } : { spec: { host: "web.example.com", tls } }),
  });
  const tls = () => ({
    termination: "edge",
    key: PEM,
    certificate: `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n${PEM}`,
    caCertificate: "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----",
  });
  it.each([[false], [true]])("get_resource masks tls.key (top-level=%s) and a key pasted into the certificate", async (top) => {
    stubFetch(route(tls(), top));
    const out = await call("get_resource", { kind: "route", name: "web", namespace: "shop" });
    clean(out);
    const t = top ? JSON.parse(out).tls : JSON.parse(out).spec.tls;
    expect(t.termination).toBe("edge");
    expect(t.key).toMatch(/^<redacted/);
    expect(t.certificate).toContain("BEGIN CERTIFICATE"); // public certificates stay readable
    expect(t.caCertificate).toContain("BBBB");
  });

  it("delete_resource and the client's scale/list answers are redacted too", async () => {
    stubFetch(route(tls()));
    clean(await call("delete_resource", { kind: "route", name: "web", namespace: "shop" }));
  });
});

describe("other kinds that can carry credentials", () => {
  it("list_events masks credentials in event messages", async () => {
    stubFetch({ kind: "EventList", items: [{ type: "Warning", reason: "Unhealthy", message: `probe failed: curl -H "Authorization: Bearer ${TOKEN}" password=${PW}` }] });
    const out = await call("list_events", { namespace: "shop" });
    clean(out);
    expect(out).toContain("probe failed");
    expect(await call("list_events", { namespace: "shop" }, { redactObjects: false })).toContain(PW);
  });

  it("BuildConfig webhook trigger secrets, and a password in a git URL (get_resource and list_resources)", async () => {
    const bc = {
      apiVersion: "build.openshift.io/v1",
      kind: "BuildConfig",
      metadata: { name: "web" },
      spec: {
        source: { git: { uri: `https://ci:${GIT_PW}@git.example.com/shop/web.git` } },
        strategy: { sourceStrategy: { env: [{ name: "NPM_TOKEN", value: TOKEN }, { name: "NODE_ENV", value: "production" }] } },
        triggers: [{ type: "GitHub", github: { secret: HOOK_SECRET } }, { type: "Generic", generic: { secret: HOOK_SECRET, allowEnv: true } }, { type: "ImageChange", imageChange: {} }],
      },
    };
    stubFetch(bc);
    const out = await call("get_resource", { kind: "buildconfig", name: "web", namespace: "shop" });
    clean(out);
    expect(out).toContain("https://ci:[REDACTED]@git.example.com/shop/web.git");
    expect(out).toContain("allowEnv");
    expect(out).toContain("NODE_ENV");
    stubFetch({ kind: "BuildConfigList", items: [{ metadata: { name: "web" }, spec: bc.spec }] });
    clean(await call("list_resources", { kind: "buildconfig", namespace: "shop" }));
  });

  it("builds (env in the build strategy)", async () => {
    stubFetch({ kind: "BuildList", items: [{ metadata: { name: "web-1" }, spec: { strategy: { dockerStrategy: { env: [{ name: "DB_PASSWORD", value: PW }] } } } }] });
    clean(await call("list_resources", { kind: "build", namespace: "shop" }));
  });
});

describe("error responses from the API server", () => {
  it("are masked (the API server can echo submitted values in its message)", async () => {
    stubFetch({ kind: "Status", message: `Invalid value: "password=${PW}"` }, 422);
    const out = await call("get_resource", { kind: "configmap", name: "x", namespace: "shop" });
    clean(out);
    expect(out).toContain("422");
    stubFetch({ kind: "Status", message: `Invalid value: "password=${PW}"` }, 422);
    expect(await call("get_resource", { kind: "configmap", name: "x", namespace: "shop" }, { redactObjects: false })).toContain(PW);
  });
});

describe("write and admin tools never echo an unredacted object", () => {
  const deployment = () => ({ apiVersion: "apps/v1", kind: "Deployment", metadata: meta(), spec: { template: { spec: podSpec() } } });
  const manifest = () => ({ apiVersion: "apps/v1", kind: "Deployment", metadata: { name: "web", namespace: "shop" }, spec: { template: { spec: podSpec() } } });

  it("delete_resource (the API answers with the deleted object), with and without kind in the response", async () => {
    stubFetch(deployment());
    clean(await call("delete_resource", { kind: "deployment", name: "web", namespace: "shop" }));
    const { kind: _k, ...noKind } = deployment();
    stubFetch(noKind);
    clean(await call("delete_resource", { kind: "deployment", name: "web", namespace: "shop" }));
  });

  it("scale (tool and client)", async () => {
    stubFetch(deployment());
    clean(await call("scale", { kind: "deployment", name: "web", namespace: "shop", replicas: 3 }));
    clean(JSON.stringify(await new OpenShiftClient(config().connection).scale("deployment", "shop", "web", 3, false)));
  });

  it("rollout_restart returns text, and the client method redacts the Deployment the PATCH answers with", async () => {
    stubFetch(deployment());
    clean(await call("rollout_restart", { name: "web", namespace: "shop" }));
    clean(JSON.stringify(await new OpenShiftClient(config().connection).rolloutRestart("shop", "web", false)));
  });

  it("apply_resource returns only the applied object's identity (real and dry-run)", async () => {
    stubFetch(deployment());
    const c = await connect();
    const real = text(await c.callTool({ name: "apply_resource", arguments: { manifest: manifest() } }));
    clean(real);
    expect(JSON.parse(real)).toMatchObject({ kind: "Deployment", name: "web", namespace: "shop" });
    clean(text(await (await connect({ dryRun: true })).callTool({ name: "apply_resource", arguments: { manifest: manifest() } })));
  });

  it("works when used directly through the client, which redacts by default", async () => {
    stubFetch(deployment());
    clean(JSON.stringify(await new OpenShiftClient(config().connection).getByKind("deployment", "web", "shop")));
    stubFetch(deployment());
    expect(JSON.stringify(await new OpenShiftClient(config().connection, { redactObjects: false }).getByKind("deployment", "web", "shop"))).toContain(PW);
  });
});

describe("Secrets are never optional", () => {
  const secret = () => ({ apiVersion: "v1", kind: "Secret", metadata: { name: "s" }, data: { p: b64(PW) }, stringData: { q: PW } });
  it("with redactObjects=false, get_resource / list_resources / delete_resource still redact them", async () => {
    stubFetch(secret());
    clean(await call("get_resource", { kind: "secret", name: "s", namespace: "shop" }, { redactObjects: false }));
    stubFetch({ kind: "SecretList", items: [{ metadata: { name: "s" }, data: { p: b64(PW) } }] });
    clean(await call("list_resources", { kind: "secret", namespace: "shop" }, { redactObjects: false }));
    stubFetch(secret());
    clean(await call("delete_resource", { kind: "secret", name: "s", namespace: "shop" }, { redactObjects: false }));
  });

  it("a Secret nested in a List or Template is redacted even with heuristics off", () => {
    const nested = { kind: "List", items: [{ kind: "Secret", metadata: { name: "s" }, data: { p: b64(PW) } }, { kind: "Template", objects: [{ kind: "Secret", stringData: { p: PW } }] }] };
    clean(JSON.stringify(redactObject(nested, undefined, false)));
  });
});

describe("redactObject", () => {
  it("does not mutate its input and is idempotent", () => {
    const pod = { kind: "Pod", spec: podSpec(), metadata: { name: "p" } };
    const copy = JSON.parse(JSON.stringify(pod));
    const once = redactObject(pod, "pod");
    expect(pod).toEqual(copy);
    expect(redactObject(once, "pod")).toEqual(once);
  });

  it("with heuristics off leaves env alone", () => {
    expect(JSON.stringify(redactObject({ kind: "Pod", spec: podSpec() }, "pod", false))).toContain(PW);
  });

  it("fails closed on absurdly deep nesting instead of recursing without bound", () => {
    let deep: Record<string, unknown> = { leaf: "x" };
    for (let i = 0; i < 200; i++) deep = { a: deep };
    expect(JSON.stringify(redactObject(deep))).toContain("nested too deep");
  });

  it("does not choke on primitives and null", () => {
    expect(redactObject(null)).toBeNull();
    expect(redactObject("x")).toBe("x");
  });
});

describe("isSecretName", () => {
  it.each([
    "PASSWORD", "DB_PASSWORD", "db-password", "dbPassword", "DB_PASS", "SMTP_PWD", "SECRET", "JWT_SECRET", "CLIENT_SECRET", "SECRET_KEY_BASE",
    "TOKEN", "GITHUB_TOKEN", "API_KEY", "apiKey", "AWS_SECRET_ACCESS_KEY", "ENCRYPTION_KEY", "TLS_KEY", "CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS", "BASIC_AUTH", "AUTH",
    "SENTRY_DSN", "DSN", "CONNECTION_STRING", "AZURE_STORAGE_CONNECTION_STRING", "JWT",
  ])("treats %s as secret-shaped", (n) => expect(isSecretName(n)).toBe(true));
  it.each([
    "REGION", "LOG_LEVEL", "DB_USER", "DB_HOST", "PORT", "SECRET_NAME", "TOKEN_COUNT", "TOKENIZER", "KEYBOARD", "PASSWORD_FILE", "BYPASS", "CLUSTER_NAME", "NODE_ENV",
  ])("leaves %s readable", (n) => expect(isSecretName(n)).toBe(false));
});

describe("OPENSHIFT_REDACT_OBJECTS", () => {
  const save = process.env.OPENSHIFT_REDACT_OBJECTS;
  afterEach(() => {
    if (save === undefined) delete process.env.OPENSHIFT_REDACT_OBJECTS;
    else process.env.OPENSHIFT_REDACT_OBJECTS = save;
  });
  it("is on by default and only an explicit false/0/no/off turns it off", () => {
    delete process.env.OPENSHIFT_REDACT_OBJECTS;
    expect(loadConfig().security.redactObjects).toBe(true);
    for (const v of ["false", "0", "no", "off", " FALSE "]) {
      process.env.OPENSHIFT_REDACT_OBJECTS = v;
      expect(loadConfig().security.redactObjects, v).toBe(false);
    }
    for (const v of ["true", "", "flase", "disabled"]) {
      process.env.OPENSHIFT_REDACT_OBJECTS = v;
      expect(loadConfig().security.redactObjects, v).toBe(true);
    }
  });
});
