/**
 * `verifyRequest`: an HTTP request signed under Web Bot Auth, checked
 * against the key its signer publishes, then the signer's identity.
 *
 * HTTP Message Signatures (RFC 9421) as profiled by
 * `draft-ietf-webbotauth-httpsig-protocol-00`, the revision the reference
 * implementation's ADR 0039 pins. Binding here: the key is looked up by the
 * (URL, key) pair, never by key alone; a signature is attributed only to a
 * Signature-Agent member it covers; the three outcomes of Appendix C.1, with
 * a discovery failure `unverified` and never evicting anything; `created`,
 * `expires`, `keyid` and `tag="web-bot-auth"` required; `expires` enforced by
 * the verifier's clock; known test keys refused unless the caller is testing.
 * Only Ed25519 keys are read, and the directory's `kid` must be the key's own
 * thumbprint, which is recomputed rather than trusted.
 */

import * as sf from "./sf.ts";
import { FetchError, TIMEOUT_SECONDS, checkSubject, type Fetcher } from "./fetch.ts";
import { DIRECTORY_PATH, defaultFetcher, observedAt, readDirectory, verifyIdentity } from "./identity.ts";
import { UNREACHABLE, Verification, check, type Check, type Outcome } from "./result.ts";

export const WEB_BOT_AUTH_TAG = "web-bot-auth";

/** Public keys that must never verify a production request (draft section
 * 6.8): RFC 9421's example Ed25519 key, which the drafts' vectors also use. */
export const KNOWN_TEST_KEYS_X: ReadonlySet<string> = new Set(["JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"]);

/** How far a `created` may sit in the future before it is refused. */
export const MAX_CLOCK_SKEW_SECONDS = 60;

/** The request as the verifier received it. `url` is the target URI the
 * request was for, with the scheme and authority the verifier served.
 * `headers` may carry a header more than once; values are kept in order. */
export class Request {
  readonly method: string;
  readonly url: string;
  readonly headers: readonly (readonly [string, string])[];
  constructor(method: string, url: string, headers: readonly (readonly [string, string])[] = []) {
    this.method = method;
    this.url = url;
    this.headers = headers;
  }

  static fromHeaders(method: string, url: string, headers: Headers): Request {
    const flat: [string, string][] = [];
    headers.forEach((value, name) => flat.push([name, value]));
    return new Request(method, url, flat);
  }

  /** RFC 9421 section 2.1: every instance of the field, trimmed, joined with
   * a comma and a space; `undefined` if the field is absent. */
  fieldValue(name: string): string | undefined {
    const values = this.headers
      .filter(([n]) => n.toLowerCase() === name.toLowerCase())
      .map(([, v]) => v.replace(/^[ \t]+|[ \t]+$/g, ""));
    return values.length === 0 ? undefined : values.join(", ");
  }
}

class Invalid extends Error {}
class Unverified extends Error {}

export interface VerifyRequestOptions {
  label?: string;
  fetcher?: Fetcher;
  now?: Date;
  allowTestKeys?: boolean;
  timeout?: number;
}

/** Verify one Web Bot Auth signature on `request`, then the signer's identity.
 * The result is `verifyIdentity` of the signer's host with `request.agent` and
 * `request.signature` in front. When the signer cannot be determined at all,
 * the result's subject is empty and its only check says why. */
export async function verifyRequest(request: Request, options: VerifyRequestOptions = {}): Promise<Verification> {
  const clock = options.now ?? new Date();
  const fetch = options.fetcher ?? defaultFetcher();
  const timeout = Math.min(options.timeout ?? TIMEOUT_SECONDS, TIMEOUT_SECONDS);

  let selected: Selected;
  try {
    selected = select(request, options.label);
  } catch (error) {
    if (error instanceof Invalid) return lone(clock, "invalid", error.message);
    if (error instanceof Unverified) return lone(clock, "unverified", error.message);
    throw error;
  }

  let host: string;
  try {
    host = checkSubject(new URL(selected.agentUrl).hostname);
  } catch (error) {
    return lone(clock, "unverified", `Signature-Agent ${pyRepr(selected.agentUrl)}: ${(error as FetchError).detail}`);
  }

  const directoryUrl = `https://${host}${DIRECTORY_PATH}`;
  const [directoryCheck, keys] = await readDirectory(fetch, directoryUrl, timeout);

  let signature: Check;
  try {
    signature = await verifyOne(request, selected, keys, directoryCheck, clock, options.allowTestKeys ?? false);
  } catch (error) {
    if (error instanceof Invalid) signature = check("request.signature", "invalid", error.message, { source: directoryUrl });
    else if (error instanceof Unverified) {
      signature = check("request.signature", "unverified", error.message, { source: directoryUrl });
    } else throw error;
  }

  const identity = await verifyIdentity(host, { fetcher: fetch, now: clock, timeout });
  return new Verification({
    subject: identity.subject,
    provider: identity.provider,
    status: identity.status,
    status_source: identity.status_source,
    observed_at: identity.observed_at,
    checks: [check("request.agent", "verified", selected.agentDetail, { source: selected.agentUrl }), signature, ...identity.checks],
    document: identity.document,
  });
}

function lone(clock: Date, outcome: Outcome, detail: string): Verification {
  return new Verification({
    subject: "",
    provider: "",
    status: UNREACHABLE,
    status_source: "none",
    observed_at: observedAt(clock),
    checks: [check("request.signature", outcome, detail)],
  });
}

interface Selected {
  label: string;
  inner: sf.InnerList;
  signature: Uint8Array;
  agentUrl: string;
  agentDetail: string;
}

function isString(value: sf.BareItem): value is string {
  return typeof value === "string";
}

/** Pick the signature to verify and the Signature-Agent member it covers. */
function select(request: Request, label: string | undefined): Selected {
  const rawInputs = request.fieldValue("signature-input");
  const rawSignatures = request.fieldValue("signature");
  const rawAgent = request.fieldValue("signature-agent");
  if (rawInputs === undefined || rawSignatures === undefined) {
    throw new Unverified("the request carries no Signature-Input and Signature headers");
  }
  if (rawAgent === undefined) throw new Unverified("the request carries no Signature-Agent header");
  let inputs: Map<string, sf.Member>;
  let signatures: Map<string, sf.Member>;
  try {
    inputs = sf.parseDictionary(rawInputs);
    signatures = sf.parseDictionary(rawSignatures);
  } catch (error) {
    throw new Invalid(`malformed signature headers: ${(error as Error).message}`);
  }

  const candidates = label !== undefined ? [label] : [...inputs.keys()];
  let chosen: string | undefined;
  for (const candidate of candidates) {
    const member = inputs.get(candidate);
    if (member === undefined || member.kind !== "inner-list") {
      if (label !== undefined) throw new Invalid(`no Signature-Input for label ${pyRepr(label)}`);
      continue;
    }
    if (label !== undefined || String(member.params.get("tag")) === WEB_BOT_AUTH_TAG) {
      chosen = candidate;
      break;
    }
  }
  if (chosen === undefined) throw new Unverified(`no signature carries tag=${pyRepr(WEB_BOT_AUTH_TAG)}`);
  const inner = inputs.get(chosen)!;
  if (inner.kind !== "inner-list") throw new Invalid(`Signature-Input ${pyRepr(chosen)} is not an Inner List`);
  const sigMember = signatures.get(chosen);
  if (sigMember === undefined || sigMember.kind !== "item" || !(sigMember.value instanceof Uint8Array)) {
    throw new Invalid(`no Signature byte sequence for label ${pyRepr(chosen)}`);
  }

  let agentKey: string | undefined;
  let coversBare = false;
  for (const it of inner.items) {
    if (it.value === "signature-agent") {
      if (it.params.has("key")) agentKey = String(it.params.get("key"));
      else coversBare = true;
    }
  }
  let agentValue: string;
  let kind: string;
  if (agentKey !== undefined) {
    let agentDict: Map<string, sf.Member>;
    try {
      agentDict = sf.parseDictionary(rawAgent);
    } catch (error) {
      throw new Invalid(`malformed Signature-Agent: ${(error as Error).message}`);
    }
    const member = agentDict.get(agentKey);
    if (member === undefined || member.kind !== "item" || !isString(member.value)) {
      throw new Invalid(`Signature-Agent has no String member ${pyRepr(agentKey)}`);
    }
    const typeParam = member.params.has("type") ? String(member.params.get("type")) : "directory";
    if (typeParam !== "directory") {
      throw new Unverified(`Signature-Agent type ${pyRepr(typeParam)} is not supported; only directory is`);
    }
    agentValue = member.value;
    kind = `member ${pyRepr(agentKey)}`;
  } else if (coversBare) {
    let it: sf.Item;
    try {
      it = sf.parseItem(rawAgent);
    } catch (error) {
      throw new Invalid(`malformed legacy Signature-Agent: ${(error as Error).message}`);
    }
    if (!isString(it.value)) throw new Invalid("legacy Signature-Agent is not a String");
    agentValue = it.value;
    kind = "legacy string form";
  } else {
    throw new Invalid("the signature does not cover a Signature-Agent member");
  }

  let parts: URL | undefined;
  try {
    parts = new URL(agentValue);
  } catch {
    parts = undefined;
  }
  if (
    parts === undefined ||
    parts.protocol !== "https:" ||
    !parts.hostname ||
    (parts.pathname !== "" && parts.pathname !== "/") ||
    parts.search ||
    parts.hash
  ) {
    throw new Unverified(`Signature-Agent ${pyRepr(agentValue)} is not an https origin, so the member is ignored`);
  }
  return {
    label: chosen,
    inner,
    signature: sigMember.value,
    agentUrl: agentValue,
    agentDetail: `${kind}, directory type, ${agentValue}`,
  };
}

async function verifyOne(
  request: Request,
  selected: Selected,
  keys: Record<string, unknown>[],
  directoryCheck: Check,
  clock: Date,
  allowTestKeys: boolean,
): Promise<Check> {
  const { inner, label, signature } = selected;
  const params = inner.params;
  for (const required of ["created", "expires", "keyid"]) {
    if (!params.has(required)) throw new Invalid(`signature parameters lack ${pyRepr(required)}`);
  }
  if (String(params.get("tag")) !== WEB_BOT_AUTH_TAG || !isString(params.get("tag") as sf.BareItem)) {
    throw new Invalid(`tag is ${pyReprBare(params.get("tag"))}, not ${pyRepr(WEB_BOT_AUTH_TAG)}`);
  }
  const created = params.get("created");
  const expires = params.get("expires");
  const keyid = params.get("keyid");
  if (typeof created !== "number" || typeof expires !== "number" || !isString(keyid as sf.BareItem)) {
    throw new Invalid("created and expires must be Integers and keyid a String");
  }
  const kid = keyid as string;
  const nowS = Math.floor(clock.getTime() / 1000);
  if (expires <= nowS) throw new Invalid(`expired at ${iso(expires)}`);
  if (created > nowS + MAX_CLOCK_SKEW_SECONDS) throw new Invalid(`created in the future (${iso(created)})`);
  const alg = params.get("alg");
  if (alg !== undefined && String(alg) !== "ed25519") {
    throw new Invalid(`alg ${pyReprBare(alg)} is not supported; only ed25519 is`);
  }

  const names = inner.items.map((i) => String(i.value));
  if (!names.includes("@authority") && !names.includes("@target-uri")) {
    throw new Invalid("the signature covers neither @authority nor @target-uri");
  }

  if (directoryCheck.outcome !== "verified") throw new Unverified(`key discovery failed: ${directoryCheck.detail ?? ""}`);
  const key = keys.find((k) => k["kid"] === kid);
  if (key === undefined) throw new Unverified(`keyid ${kid.slice(0, 12)}… is not in the signer's directory`);
  const thumbprint = await jwkThumbprint(key);
  if (thumbprint !== kid) {
    throw new Invalid(`the directory labels this key ${kid.slice(0, 12)}…, but its thumbprint is ${thumbprint.slice(0, 12)}…`);
  }
  if (KNOWN_TEST_KEYS_X.has(String(key["x"])) && !allowTestKeys) {
    throw new Invalid("the signing key is a published test key (RFC 9421 Appendix B.1.4)");
  }

  const base = signatureBase(request, inner);
  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey("raw", buffer(sf.base64UrlDecode(String(key["x"]))), { name: "Ed25519" }, false, [
      "verify",
    ]);
  } catch (error) {
    throw new Invalid(`unreadable Ed25519 key: ${(error as Error).message}`);
  }
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, buffer(signature), buffer(new TextEncoder().encode(base)));
  if (!ok) throw new Invalid("the signature does not verify over the covered components");

  const covered = inner.items.map(sf.serializeItem).join(" ");
  const remaining = expires - nowS;
  const when = remaining < 86400 ? `expires in ${Math.floor(remaining / 60)}m` : `expires ${iso(expires)}`;
  return check("request.signature", "verified", `ed25519, label ${label}, kid ${kid.slice(0, 12)}…, covers ${covered}, ${when}`);
}

// -- RFC 9421 section 2: the signature base ---------------------------------

/** The signature base for `inner` (the label's Signature-Input member) over
 * `request`, per RFC 9421 section 2.5. Throws when a component cannot be derived. */
export function signatureBase(request: Request, inner: sf.InnerList): string {
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const it of inner.items) {
    const identifier = sf.serializeItem(it);
    if (seen.has(identifier)) throw new Invalid(`component ${identifier} is covered twice`);
    seen.add(identifier);
    if (!isString(it.value)) throw new Invalid(`component identifier ${identifier} is not a String`);
    const name = it.value;
    const value = name.startsWith("@") ? derived(request, name, it.params) : field(request, name, it.params);
    lines.push(`${identifier}: ${value}`);
  }
  lines.push(`"@signature-params": ${sf.serializeInnerList(inner)}`);
  const base = lines.join("\n");
  // eslint-disable-next-line no-control-regex
  if (/[^\x00-\x7f]/.test(base)) throw new Invalid("the signature base is not ASCII");
  return base;
}

function derived(request: Request, name: string, params: sf.Params): string {
  if (params.has("req")) throw new Invalid(`${name};req is only valid on a response`);
  const parts = new URL(request.url);
  const noParams = () => {
    if (params.size > 0) throw new Invalid(`${name} takes no parameters`);
  };
  switch (name) {
    case "@method":
      noParams();
      return request.method.toUpperCase();
    case "@target-uri":
      noParams();
      return request.url;
    case "@authority": {
      noParams();
      const host = parts.hostname.toLowerCase();
      // URL drops a default port; a non-default one is kept.
      return parts.port ? `${host}:${parts.port}` : host;
    }
    case "@scheme":
      noParams();
      return parts.protocol.replace(/:$/, "").toLowerCase();
    case "@request-target":
      noParams();
      return `${parts.pathname || "/"}${parts.search}`;
    case "@path":
      noParams();
      return parts.pathname || "/";
    case "@query":
      noParams();
      return `?${parts.search.replace(/^\?/, "")}`;
    case "@query-param": {
      const wanted = params.get("name");
      if (!isString(wanted as sf.BareItem) || params.size !== 1) {
        throw new Invalid("@query-param needs exactly one parameter, name");
      }
      const found = new URLSearchParams(parts.search).getAll(wanted as string);
      if (found.length !== 1) throw new Invalid(`@query-param ${pyRepr(wanted as string)} occurs ${found.length} times`);
      return percentEncode(found[0]!);
    }
    default:
      throw new Invalid(`derived component ${pyRepr(name)} is not supported`);
  }
}

/** RFC 3986 percent-encoding of everything but the unreserved set, as
 * Python's `quote(value, safe="")`. */
function percentEncode(value: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(value)) {
    const c = String.fromCharCode(byte);
    if (/[A-Za-z0-9\-._~]/.test(c)) out += c;
    else out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

function field(request: Request, name: string, params: sf.Params): string {
  if (name !== name.toLowerCase()) throw new Invalid(`field name ${pyRepr(name)} must be lowercase`);
  const unknown = [...params.keys()].filter((k) => !["key", "sf", "bs", "tr"].includes(k)).sort();
  if (unknown.length > 0) throw new Invalid(`field parameter(s) [${unknown.map(pyRepr).join(", ")}] are not understood`);
  if (params.has("bs") || params.has("tr")) throw new Invalid("the bs and tr field parameters are not supported");
  const value = request.fieldValue(name);
  if (value === undefined) throw new Invalid(`the request has no ${name} field`);
  if (params.has("key")) {
    const key = params.get("key");
    if (!isString(key as sf.BareItem)) throw new Invalid("the key parameter must be a String");
    let members: Map<string, sf.Member>;
    try {
      members = sf.parseDictionary(value);
    } catch (error) {
      throw new Invalid(`${name} is not a Dictionary: ${(error as Error).message}`);
    }
    const member = members.get(key as string);
    if (member === undefined) throw new Invalid(`${name} has no member ${pyRepr(key as string)}`);
    return sf.serializeMember(member);
  }
  if (params.has("sf")) {
    try {
      return value.startsWith("(") ? value : sf.serializeMember(sf.parseItem(value));
    } catch (error) {
      throw new Invalid(`${name};sf is not a Structured Field: ${(error as Error).message}`);
    }
  }
  return value;
}

// -- keys --------------------------------------------------------------------

/** RFC 7638 thumbprint of an OKP key (RFC 8037 Appendix A.3): `crv`, `kty`
 * and `x` in lexicographic order, no whitespace, SHA-256, base64url. */
export async function jwkThumbprint(key: Record<string, unknown>): Promise<string> {
  const canonical = JSON.stringify({ crv: key["crv"] ?? null, kty: key["kty"] ?? null, x: key["x"] ?? null });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return sf.base64UrlEncode(new Uint8Array(digest));
}

/** A plain ArrayBuffer copy, which WebCrypto's types require. */
function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function iso(seconds: number): string {
  return new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function pyRepr(value: string): string {
  return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}

function pyReprBare(value: sf.BareItem | undefined): string {
  if (value === undefined) return "None";
  if (typeof value === "string") return pyRepr(value);
  if (value instanceof sf.Token) return pyRepr(value.value);
  if (typeof value === "boolean") return value ? "True" : "False";
  if (typeof value === "number") return String(value);
  if (value instanceof sf.Decimal) return String(value.value);
  return `b'...'`;
}
