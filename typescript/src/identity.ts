/**
 * `verifyIdentity`: read one identity's public record and report each check.
 *
 * What is read, and from where: the Agent Identity Document at
 * `/.well-known/agent-identity.json` over HTTPS (no redirects); the document
 * against the specification's JSON Schema at the tag this package bundles;
 * the owner block (each itemised, dated check and the account's standing);
 * the Web Bot Auth key directory; and the provider's signed statement about
 * the document, once providers serve one.
 *
 * What is never read: a status file or badge that summarises the document (a
 * rendering, not a source), the A2A agent card, or the agent's endpoints,
 * which are reported as listed and never probed.
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import {
  CachingFetcher,
  DefaultFetcher,
  FetchError,
  MAX_DIRECTORY_BYTES,
  MAX_DOCUMENT_BYTES,
  TIMEOUT_SECONDS,
  checkSubject,
  type Fetched,
  type Fetcher,
} from "./fetch.ts";
import { UNKNOWN, UNREACHABLE, Verification, check, type Check } from "./result.ts";

export const DOCUMENT_PATH = "/.well-known/agent-identity.json";
export const DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const STATEMENT_PATH = "/.well-known/agent-identity-statement.jws";

/** The specification tag whose schema this package bundles. */
export const SCHEMA_TAG = "v1.0.1-draft";

export const DOCUMENT_MEDIA_TYPE = "application/json";
export const DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";

/** Cache lifetimes the reference implementation serves; a cap, never a floor. */
export const CACHE_CAPS: Readonly<Record<string, number>> = {
  [DOCUMENT_PATH]: 60,
  [DIRECTORY_PATH]: 300,
};

/** At most this many keys are read from a directory (draft section 6.7). */
export const MAX_DIRECTORY_KEYS = 16;

export const SCHEMA_URL = new URL("../schema/agent-identity-document.schema.json", import.meta.url);

let validator: ((data: unknown) => boolean) | undefined;

type AjvLike = new (options: object) => { compile(schema: object): (data: unknown) => boolean };

function schemaValidator(): (data: unknown) => boolean {
  if (validator === undefined) {
    const schema = JSON.parse(readFileSync(SCHEMA_URL, "utf8")) as object;
    // Formats are not asserted, as in the Python implementation (jsonschema
    // without a format checker); the dates the checks use are parsed there.
    // ajv ships CommonJS; `createRequire` keeps the import ESM-clean.
    const load = createRequire(import.meta.url);
    const Ajv2020 = load("ajv/dist/2020.js") as AjvLike;
    const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: false });
    validator = ajv.compile(schema) as (data: unknown) => boolean;
  }
  return validator;
}

/** The fetcher used when a caller passes none. */
export function defaultFetcher(): Fetcher {
  return new CachingFetcher(new DefaultFetcher(), CACHE_CAPS);
}

/** The provider behind a subject: the last two labels of a name with three or
 * more, else the name itself. A heuristic, stated as one. */
export function providerOf(hostname: string): string {
  const labels = hostname.split(".");
  return labels.length >= 3 ? labels.slice(-2).join(".") : hostname;
}

export interface VerifyIdentityOptions {
  fetcher?: Fetcher;
  /** The verifier's clock (UTC), used only to decide whether a published check has expired. */
  now?: Date;
  providers?: readonly string[];
  /** Seconds; capped at `TIMEOUT_SECONDS`. */
  timeout?: number;
}

export function observedAt(clock: Date): string {
  return clock.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export async function verifyIdentity(
  subject: string,
  options: VerifyIdentityOptions = {},
): Promise<Verification> {
  const clock = options.now ?? new Date();
  const observed = observedAt(clock);
  const fetch = options.fetcher ?? defaultFetcher();
  const timeout = Math.min(options.timeout ?? TIMEOUT_SECONDS, TIMEOUT_SECONDS);

  let host: string;
  try {
    host = checkSubject(subject);
  } catch (error) {
    return new Verification({
      subject: subject.trim().toLowerCase(),
      provider: "",
      status: UNREACHABLE,
      status_source: "none",
      observed_at: observed,
      checks: [check("document.fetched", "unverified", (error as FetchError).detail)],
    });
  }

  const provider = providerOf(host);
  const checks: Check[] = [];

  if (options.providers !== undefined) {
    const allowed = options.providers.map((p) => p.toLowerCase());
    if (!allowed.some((p) => host === p || host.endsWith(`.${p}`))) {
      return new Verification({
        subject: host,
        provider,
        status: UNREACHABLE,
        status_source: "none",
        observed_at: observed,
        checks: [
          check(
            "document.fetched",
            "unverified",
            `${provider} is not among the providers this verifier accepts`,
          ),
        ],
      });
    }
  }

  const documentUrl = `https://${host}${DOCUMENT_PATH}`;
  let status = UNREACHABLE;
  let statusSource = "none";
  let document: Record<string, unknown> | null = null;

  try {
    const response = await fetch.get(documentUrl, {
      accept: DOCUMENT_MEDIA_TYPE,
      maxBytes: MAX_DOCUMENT_BYTES,
      timeout,
    });
    if (response.status === 404) {
      status = UNKNOWN;
      statusSource = "document";
      checks.push(
        check(
          "document.fetched",
          "verified",
          `404: no identity is published at this name${headerNote(response)}`,
          { source: documentUrl },
        ),
      );
    } else if (response.status !== 200) {
      checks.push(
        check(
          "document.fetched",
          "unverified",
          `HTTP ${response.status}; only 200 and 404 are answers`,
          { source: documentUrl },
        ),
      );
    } else {
      const [parsed, parseError] = parseJson(response);
      if (parsed === null) {
        checks.push(check("document.fetched", "invalid", parseError ?? "not JSON", { source: documentUrl }));
      } else {
        document = parsed;
        checks.push(
          check(
            "document.fetched",
            "verified",
            `HTTPS, 200, ${contentType(response)}, ${size(response)}`,
            { source: documentUrl },
          ),
        );
        checks.push(schemaCheck(document));
        checks.push(hostCheck(document, host));
        const published = document["status"];
        if (typeof published === "string" && published) {
          status = published;
          statusSource = "document";
        }
        checks.push(...ownerChecks(document, clock));
      }
    }
  } catch (error) {
    checks.push(check("document.fetched", "unverified", (error as FetchError).detail, { source: documentUrl }));
  }

  const directoryUrl = `https://${host}${DIRECTORY_PATH}`;
  const [directory] = await readDirectory(fetch, directoryUrl, timeout);
  checks.push(directory);

  const statementUrl = `https://${host}${STATEMENT_PATH}`;
  checks.push(await statementCheck(fetch, statementUrl, timeout));

  return new Verification({
    subject: host,
    provider,
    status,
    status_source: statusSource,
    observed_at: observed,
    checks,
    document,
  });
}

function headerNote(response: Fetched): string {
  const wanted = ["x-content-type-options", "access-control-allow-origin"];
  const missing = wanted.filter((name) => response.header(name) === undefined);
  return missing.length === 0 ? "" : ` (without ${missing.join(", ")})`;
}

export function contentType(response: Fetched): string {
  return (response.header("content-type") ?? "no content-type").split(";")[0]!.trim();
}

function size(response: Fetched): string {
  const n = response.body.length;
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} kB`;
}

function parseJson(response: Fetched): [Record<string, unknown> | null, string | null] {
  if (!contentType(response).endsWith("json")) {
    return [null, `served as ${contentType(response)}, not JSON`];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body));
  } catch (error) {
    return [null, `not JSON: ${(error as Error).message}`];
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return [null, "not a JSON object"];
  }
  return [parsed as Record<string, unknown>, null];
}

function schemaCheck(document: Record<string, unknown>): Check {
  if (schemaValidator()(document)) {
    return check("document.schema", "verified", `agent-identity-document.schema.json ${SCHEMA_TAG}`);
  }
  return check(
    "document.schema",
    "invalid",
    `does not match agent-identity-document.schema.json ${SCHEMA_TAG}`,
  );
}

function hostCheck(document: Record<string, unknown>, host: string): Check {
  const fqdn = document["fqdn"];
  if (fqdn === host) return check("document.host", "verified", `fqdn is ${host}`);
  return check("document.host", "invalid", `fqdn is ${pyRepr(fqdn)}, fetched from ${host}`);
}

/** Python's repr for the few shapes a document member can take, so the
 * detail matches the other implementation byte for byte. */
function pyRepr(value: unknown): string {
  if (typeof value === "string") return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
  if (value === undefined || value === null) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  return JSON.stringify(value);
}

function ownerChecks(document: Record<string, unknown>, clock: Date): Check[] {
  const owner = document["owner"];
  if (typeof owner !== "object" || owner === null || Array.isArray(owner)) {
    const why =
      document["status"] === "suspended"
        ? "a suspended identity publishes no owner block"
        : "the document carries no owner block";
    return [check("owner.standing", "absent", why)];
  }
  const block = owner as Record<string, unknown>;
  const checks: Check[] = [];
  const verifications = Array.isArray(block["verifications"]) ? (block["verifications"] as unknown[]) : [];
  for (const entry of verifications) {
    if (typeof entry !== "object" || entry === null || typeof (entry as Record<string, unknown>)["type"] !== "string") {
      checks.push(check("owner.unknown", "invalid", "a check without a type"));
      continue;
    }
    const e = entry as Record<string, unknown>;
    const name = `owner.${e["type"] as string}`;
    const verifiedAt = e["verified_at"];
    const expiresAt = e["expires_at"];
    const parts: string[] = [];
    if (e["value"]) parts.push(`controls ${String(e["value"])}`);
    if (e["method"]) parts.push(String(e["method"]));
    if (e["verifier"]) parts.push(`by ${String(e["verifier"])}`);
    let detail = parts.join(", ");
    let outcome: Check["outcome"] = "verified";
    if (typeof verifiedAt !== "string" || parseTime(verifiedAt) === null) {
      outcome = "invalid";
      detail = "no readable verified_at";
    } else if (typeof expiresAt === "string") {
      const expiry = parseTime(expiresAt);
      if (expiry === null) {
        outcome = "invalid";
        detail = "unreadable expires_at";
      } else if (expiry.getTime() <= clock.getTime()) {
        outcome = "invalid";
        detail = `${detail ? `${detail}; ` : ""}expired ${expiresAt}`;
      }
    }
    const extra: { verified_at?: string; expires_at?: string } = {};
    if (typeof verifiedAt === "string") extra.verified_at = verifiedAt;
    if (typeof expiresAt === "string") extra.expires_at = expiresAt;
    checks.push(check(name, outcome, detail, extra));
  }
  const standing = block["standing"];
  if (typeof standing === "object" && standing !== null && (standing as Record<string, unknown>)["status"] === "active") {
    const since = (standing as Record<string, unknown>)["account_since"] ?? "?";
    checks.push(check("owner.standing", "verified", `account since ${String(since)}, active`));
  } else {
    checks.push(check("owner.standing", "invalid", "standing is not active"));
  }
  return checks;
}

export function parseTime(value: string): Date | null {
  // RFC 3339 only: a date-time with an offset or Z. Date.parse is broader
  // (it accepts "2026-10-02" alone), so require the time part.
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(value)) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/** Fetch and validate a key directory. The keys are returned only when the
 * check is `verified`; otherwise the list is empty and the check says why.
 * A 404 or a failed fetch is a discovery failure, `unverified`: not evidence
 * about any key a verifier already holds (draft section 6.10). */
export async function readDirectory(
  fetch: Fetcher,
  url: string,
  timeout: number,
): Promise<[Check, Record<string, unknown>[]]> {
  let response: Fetched;
  try {
    response = await fetch.get(url, { accept: DIRECTORY_MEDIA_TYPE, maxBytes: MAX_DIRECTORY_BYTES, timeout });
  } catch (error) {
    return [
      check("keys.directory", "unverified", `discovery failed: ${(error as FetchError).detail}`, { source: url }),
      [],
    ];
  }
  if (response.status !== 200) {
    return [check("keys.directory", "unverified", `discovery failed: HTTP ${response.status}`, { source: url }), []];
  }
  if (contentType(response) !== DIRECTORY_MEDIA_TYPE) {
    return [
      check("keys.directory", "invalid", `served as ${contentType(response)}, not ${DIRECTORY_MEDIA_TYPE}`, {
        source: url,
      }),
      [],
    ];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(response.body));
  } catch (error) {
    return [check("keys.directory", "invalid", `not JSON: ${(error as Error).message}`, { source: url }), []];
  }
  const keys = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>)["keys"] : undefined;
  if (!Array.isArray(keys)) return [check("keys.directory", "invalid", "no keys array", { source: url }), []];
  if (keys.length > MAX_DIRECTORY_KEYS) {
    return [
      check("keys.directory", "invalid", `${keys.length} keys; at most ${MAX_DIRECTORY_KEYS} are read`, { source: url }),
      [],
    ];
  }
  for (const key of keys) {
    const problem = keyProblem(key);
    if (problem) return [check("keys.directory", "invalid", problem, { source: url }), []];
  }
  const count = keys.length;
  const detail = count === 0 ? "no active keys" : `${count} active key${count !== 1 ? "s" : ""}`;
  return [check("keys.directory", "verified", detail, { source: url }), keys as Record<string, unknown>[]];
}

function keyProblem(key: unknown): string | null {
  if (typeof key !== "object" || key === null || Array.isArray(key)) return "a key that is not an object";
  const k = key as Record<string, unknown>;
  if (k["kty"] !== "OKP" || k["crv"] !== "Ed25519") {
    return `unsupported key type ${pyRepr(k["kty"])}/${pyRepr(k["crv"])}; only Ed25519 is read`;
  }
  if (typeof k["x"] !== "string" || typeof k["kid"] !== "string") return "a key without x or kid";
  return null;
}

async function statementCheck(fetch: Fetcher, url: string, timeout: number): Promise<Check> {
  let response: Fetched;
  try {
    response = await fetch.get(url, { accept: "application/jose", maxBytes: MAX_DOCUMENT_BYTES, timeout });
  } catch (error) {
    return check("platform.statement", "unverified", `not fetched: ${(error as FetchError).detail}`, { source: url });
  }
  if (response.status === 404) {
    return check("platform.statement", "absent", "no signed statement is served for this document yet", {
      source: url,
    });
  }
  if (response.status !== 200) {
    return check("platform.statement", "unverified", `HTTP ${response.status}`, { source: url });
  }
  return check(
    "platform.statement",
    "unverified",
    "a statement is served, but this version does not verify statements yet",
    { source: url },
  );
}
