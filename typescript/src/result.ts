/**
 * The result of a verification: a list of checks, each saying what was looked
 * at and what came of it. There is no trust flag, score or level anywhere in
 * this module, and no function returns one.
 *
 * A caller who needs a yes-or-no writes it from the checks it depends on, by
 * name, with `require` or `assertVerified`, so the policy lives in the
 * caller's code and names what it rests on.
 */

/** The four outcomes. `verified`, `invalid` and `unverified` are the Web Bot
 * Auth draft's (Appendix C.1): a fetch that failed is `unverified`, never
 * `invalid` and never `verified`. `absent` is for a thing the record does not
 * carry. */
export type Outcome = "verified" | "invalid" | "unverified" | "absent";

/** The host answered 404 at the document's URI: "no identity is published here". */
export const UNKNOWN = "unknown";
/** Nothing that could be read came back. Never merged with `unknown`. */
export const UNREACHABLE = "unreachable";

export interface Check {
  readonly name: string;
  readonly outcome: Outcome;
  /** Absent when empty, so the JSON form matches the other implementations. */
  readonly detail?: string;
  readonly source?: string;
  /** Copied from the record as published (RFC 3339), never reformatted. */
  readonly verified_at?: string;
  readonly expires_at?: string;
}

export function check(
  name: string,
  outcome: Outcome,
  detail = "",
  extra: { source?: string; verified_at?: string; expires_at?: string } = {},
): Check {
  const out: { -readonly [K in keyof Check]: Check[K] } = { name, outcome };
  if (detail) out.detail = detail;
  if (extra.source !== undefined) out.source = extra.source;
  if (extra.verified_at !== undefined) out.verified_at = extra.verified_at;
  if (extra.expires_at !== undefined) out.expires_at = extra.expires_at;
  return out;
}

export interface VerificationInit {
  subject: string;
  provider: string;
  status: string;
  status_source: string;
  observed_at: string;
  checks?: readonly Check[];
  document?: Record<string, unknown> | null;
}

/** What was checked about one subject, and when. `status` is the document's
 * own `status` member when a document was served, or `unknown` or
 * `unreachable`. It is read, never computed. */
export class Verification {
  readonly subject: string;
  readonly provider: string;
  readonly status: string;
  readonly status_source: string;
  readonly observed_at: string;
  readonly checks: readonly Check[];
  /** The parsed document, for members the checks do not cover. Not in `toJSON`. */
  readonly document: Record<string, unknown> | null;

  constructor(init: VerificationInit) {
    this.subject = init.subject;
    this.provider = init.provider;
    this.status = init.status;
    this.status_source = init.status_source;
    this.observed_at = init.observed_at;
    this.checks = init.checks ?? [];
    this.document = init.document ?? null;
  }

  /** The check called `name`, or `undefined` if the library did not run it. */
  check(name: string): Check | undefined {
    return this.checks.find((c) => c.name === name);
  }

  /** Every check whose name starts with `prefix` (`"owner."` for all owner checks). */
  outcomes(prefix: string): Check[] {
    return this.checks.filter((c) => c.name.startsWith(prefix));
  }

  toJSON(): {
    subject: string;
    provider: string;
    status: string;
    status_source: string;
    observed_at: string;
    checks: Check[];
  } {
    return {
      subject: this.subject,
      provider: this.provider,
      status: this.status,
      status_source: this.status_source,
      observed_at: this.observed_at,
      checks: [...this.checks],
    };
  }
}

/** Raised by `assertVerified`; names the checks that were not `verified`. */
export class VerificationFailed extends Error {
  readonly verification: Verification;
  readonly failed: readonly (Check | string)[];

  constructor(verification: Verification, failed: readonly (Check | string)[]) {
    const parts = failed.map((item) =>
      typeof item === "string"
        ? `${item}: not checked`
        : `${item.name}: ${item.outcome}${item.detail ? ` (${item.detail})` : ""}`,
    );
    super(`${verification.subject}: ${parts.join("; ")}`);
    this.name = "VerificationFailed";
    this.verification = verification;
    this.failed = failed;
  }
}

/** `true` only if every named check ran and is `verified`. A check the
 * library did not run counts as a failure, so a typo in a name cannot pass. */
export function require(verification: Verification, ...names: string[]): boolean {
  if (names.length === 0) throw new TypeError("require() needs at least one check name");
  return names.every((name) => verification.check(name)?.outcome === "verified");
}

/** Like `require`, but throws `VerificationFailed` naming each failure. */
export function assertVerified(verification: Verification, ...names: string[]): void {
  if (names.length === 0) throw new TypeError("assertVerified() needs at least one check name");
  const failed: (Check | string)[] = [];
  for (const name of names) {
    const c = verification.check(name);
    if (c === undefined) failed.push(name);
    else if (c.outcome !== "verified") failed.push(c);
  }
  if (failed.length > 0) throw new VerificationFailed(verification, failed);
}
