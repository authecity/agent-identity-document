/**
 * Bounded HTTPS fetches of public records, and nothing else.
 *
 * Every network access the library makes goes through a `Fetcher`. The
 * default applies the limits the Web Bot Auth draft asks of verifiers
 * (section 6.7): a byte limit, a wall-clock timeout, no redirects, and no
 * private, loopback or link-local addresses. It speaks HTTPS only and never
 * sends anything that identifies the verifier's own users.
 *
 * Tests pass a `RecordedFetcher` built from fixtures, so the suite runs
 * without a network.
 */

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export const VERSION = "0.1.0";
export const USER_AGENT = `knownas-verify/${VERSION} (+https://github.com/authecity/agent-identity-document)`;

/** A hostname as the Agent Identity Document schema defines it. */
const HOSTNAME = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

/** Limits (ADR 0049 section 3.1). A caller may lower them, never raise them. */
export const MAX_DOCUMENT_BYTES = 64 * 1024;
export const MAX_DIRECTORY_BYTES = 64 * 1024;
export const TIMEOUT_SECONDS = 5;

/** A fetch that produced nothing readable. `kind` is one word: `refused`
 * (the library would not make the request), `redirect`, `too_large`,
 * `timeout` or `network`. */
export class FetchError extends Error {
  readonly kind: string;
  readonly detail: string;
  constructor(kind: string, detail: string) {
    super(`${kind}: ${detail}`);
    this.name = "FetchError";
    this.kind = kind;
    this.detail = detail;
  }
}

/** What came back: the status, the headers with lowercase names, the body. */
export class Fetched {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
  constructor(status: number, headers: Readonly<Record<string, string>>, body: Uint8Array) {
    this.status = status;
    this.headers = headers;
    this.body = body;
  }

  header(name: string): string | undefined {
    return this.headers[name.toLowerCase()];
  }

  /** `max-age` from `Cache-Control`, if present and a whole number. */
  maxAge(): number | undefined {
    const value = this.header("cache-control") ?? "";
    for (const directive of value.split(",")) {
      const [key, number] = directive.trim().split("=", 2);
      if (key?.trim().toLowerCase() === "max-age" && number !== undefined && /^\d+$/.test(number.trim())) {
        return Number.parseInt(number.trim(), 10);
      }
    }
    return undefined;
  }
}

export interface FetchOptions {
  accept: string;
  maxBytes: number;
  /** Seconds. */
  timeout: number;
}

export interface Fetcher {
  get(url: string, options: FetchOptions): Promise<Fetched>;
}

/** Normalise and validate a subject hostname, or throw `FetchError` with kind
 * `refused`. Refuses IP literals and anything the schema's pattern does not accept. */
export function checkSubject(hostname: string): string {
  const name = hostname.trim().replace(/\.+$/, "").toLowerCase();
  if (!name || name.length > 253) throw new FetchError("refused", "not a hostname");
  if (isIP(name.replace(/^\[|\]$/g, "")) !== 0) {
    throw new FetchError("refused", "IP literals are not identities");
  }
  if (!HOSTNAME.test(name)) throw new FetchError("refused", "not a hostname");
  return name;
}

/** Whether an address is globally reachable: false for every special-purpose
 * range (private, loopback, link-local, shared address space 100.64/10,
 * documentation, multicast, reserved, unspecified, unique-local). */
export function isGlobal(address: string): boolean {
  const kind = isIP(address);
  if (kind === 4) {
    const parts = address.split(".").map((p) => Number.parseInt(p, 10));
    const [a = 0, b = 0, c = 0] = parts;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 0 && c === 0) return false;
    if (a === 192 && b === 0 && c === 2) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    if (a >= 224) return false;
    return true;
  }
  if (kind === 6) {
    const lower = address.toLowerCase().split("%")[0]!;
    if (lower === "::" || lower === "::1") return false;
    if (lower.startsWith("::ffff:")) return isGlobal(lower.slice(7));
    const head = Number.parseInt(lower.split(":")[0] || "0", 16);
    if ((head & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
    if ((head & 0xffc0) === 0xfe80) return false; // fe80::/10 link local
    if ((head & 0xff00) === 0xff00) return false; // ff00::/8 multicast
    if (head === 0x2001 && lower.startsWith("2001:db8")) return false; // documentation
    if (head === 0x100) return false; // 100::/64 discard
    return true;
  }
  return false;
}

/** Resolve `hostname` and refuse it if any address is not globally reachable
 * (draft section 6.7). This checks what the resolver returns now; a host whose
 * records change before the connection is the rebinding case a library cannot
 * close on its own. */
export async function refusePrivateAddresses(hostname: string): Promise<void> {
  let infos: { address: string }[];
  try {
    infos = await lookup(hostname, { all: true });
  } catch (error) {
    throw new FetchError("network", `name does not resolve: ${String((error as Error).message ?? error)}`);
  }
  if (infos.length === 0) throw new FetchError("network", "name does not resolve");
  for (const info of infos) {
    if (!isGlobal(info.address)) {
      throw new FetchError("refused", `resolves to a non-public address (${info.address})`);
    }
  }
}

/** The default fetcher: HTTPS only, certificate checked, no redirects,
 * bounded body, bounded time, public addresses only. */
export class DefaultFetcher implements Fetcher {
  async get(url: string, options: FetchOptions): Promise<Fetched> {
    if (!url.startsWith("https://")) throw new FetchError("refused", "only https URLs are fetched");
    const host = url.slice("https://".length).split("/", 1)[0]!.split(":", 1)[0]!;
    await refusePrivateAddresses(checkSubject(host));
    const timeoutMs = Math.max(1, Math.floor(options.timeout * 1000));
    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        headers: { Accept: options.accept, "User-Agent": USER_AGENT },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const name = (error as Error)?.name ?? "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new FetchError("timeout", `no answer within ${options.timeout.toFixed(0)}s`);
      }
      const cause = (error as { cause?: Error }).cause;
      throw new FetchError("network", String(cause?.message ?? (error as Error).message ?? error));
    }
    if (response.status >= 300 && response.status < 400) {
      const where = response.headers.get("location") ?? "?";
      throw new FetchError("redirect", `${response.status} to ${where}; redirects are not followed`);
    }
    const body = await readBounded(response, options.maxBytes);
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return new Fetched(response.status, headers, body);
  }
}

async function readBounded(response: Response, maxBytes: number): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new FetchError("too_large", `body exceeds ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** A fetcher that answers from a map of URL to response, for tests and
 * fixtures. A URL that is not recorded throws a `network` error, and a
 * recorded `FetchError` is thrown as given. */
export class RecordedFetcher implements Fetcher {
  readonly calls: string[] = [];
  readonly responses: Map<string, Fetched | FetchError>;
  constructor(responses: Map<string, Fetched | FetchError>) {
    this.responses = responses;
  }

  async get(url: string, options: FetchOptions): Promise<Fetched> {
    this.calls.push(url);
    const answer = this.responses.get(url);
    if (answer === undefined) throw new FetchError("network", `not recorded: ${url}`);
    if (answer instanceof FetchError) throw answer;
    if (answer.body.length > options.maxBytes) {
      throw new FetchError("too_large", `body exceeds ${options.maxBytes} bytes`);
    }
    return answer;
  }
}

/** Honours `Cache-Control: max-age` up to a per-URL-path cap, so a verifier
 * that checks many requests does not refetch the same record each time. Caps
 * are the platform's own lifetimes; a caller may lower them, never raise them.
 * A failed fetch is never cached (draft section 6.10). */
export class CachingFetcher implements Fetcher {
  private readonly entries = new Map<string, { until: number; response: Fetched }>();
  readonly inner: Fetcher;
  readonly caps: Readonly<Record<string, number>>;
  readonly clock: () => number;

  constructor(inner: Fetcher, caps: Readonly<Record<string, number>>, clock: () => number = () => Date.now() / 1000) {
    this.inner = inner;
    this.caps = caps;
    this.clock = clock;
  }

  async get(url: string, options: FetchOptions): Promise<Fetched> {
    const now = this.clock();
    const cached = this.entries.get(url);
    if (cached !== undefined && cached.until > now) return cached.response;
    const response = await this.inner.get(url, options);
    let cap = 0;
    for (const [path, seconds] of Object.entries(this.caps)) {
      if (url.endsWith(path)) cap = seconds;
    }
    const age = response.maxAge();
    if (response.status === 200 && age !== undefined && cap > 0) {
      this.entries.set(url, { until: now + Math.min(age, cap), response });
    }
    return response;
  }
}
