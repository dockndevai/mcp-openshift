/**
 * Secret redaction: credentials must never reach the model. A Secret's values live in `data` (base64) and
 * `stringData` (plain), and `kubectl apply` also stores the whole object, values included, in the
 * `kubectl.kubernetes.io/last-applied-configuration` annotation. Keys and sizes are kept so the model can still
 * see what a Secret holds.
 *
 * The API server omits `kind` on the items of a typed list, so a Secret list item cannot be recognised by itself:
 * callers that know the object or list is of Secrets (from the kind they requested) pass `asSecret`.
 */

const LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration";

type Obj = Record<string, unknown>;

function redactValues(values: unknown, size: (v: string) => number): Obj | undefined {
  if (!values || typeof values !== "object") return undefined;
  const out: Obj = {};
  for (const [k, v] of Object.entries(values as Obj)) out[k] = `<redacted, ${typeof v === "string" ? size(v) : 0} bytes>`;
  return out;
}

/** Returns a copy of `obj` with Secret values removed; anything that is not (a list of) Secrets is returned as is. */
export function redactSecret<T>(obj: T, asSecret = false): T {
  if (!obj || typeof obj !== "object") return obj;
  const o = obj as Obj;
  if (Array.isArray(o.items)) {
    // A list: Secrets if it says so, or the caller asked for Secrets; a generic List redacts each item by its own kind.
    const secrets = asSecret || o.kind === "SecretList";
    return { ...o, items: o.items.map((i) => redactSecret(i, secrets)) } as T;
  }
  if (o.kind !== "Secret" && !asSecret) return obj;
  const out: Obj = { ...o };
  const data = redactValues(o.data, (v) => Buffer.from(v, "base64").length);
  if (data) out.data = data;
  const stringData = redactValues(o.stringData, (v) => Buffer.byteLength(v));
  if (stringData) out.stringData = stringData;
  const md = o.metadata as Obj | undefined;
  const ann = md?.annotations as Obj | undefined;
  if (md && ann && LAST_APPLIED in ann) out.metadata = { ...md, annotations: { ...ann, [LAST_APPLIED]: "<redacted>" } };
  return out as T;
}
