/**
 * `summarise`: the checks as short sentences for people.
 *
 * Each sentence states what was checked and when, in the wording the
 * reference implementation's ADR 0037 allows ("Owner controls the domain name acme.example,
 * checked 2026-10-02, renews 2026-11-01"). None of them says "trusted",
 * "verified owner" without an object, a number, or a colour. A badge or a
 * listing that prints anything should print these.
 */

import {
  UNKNOWN,
  UNREACHABLE,
  type Check,
  type Verification,
} from "./result.ts";

/** Words these sentences never use. Tested. */
export const FORBIDDEN_WORDS = [
  "trusted",
  "trustworthy",
  "safe",
  "verified owner",
  "level",
  "score",
] as const;

export function summarise(verification: Verification): string[] {
  const lines = [statusLine(verification)];
  for (const c of verification.outcomes("owner.")) {
    const line = ownerLine(c);
    if (line) lines.push(line);
  }
  const directory = verification.check("keys.directory");
  if (directory !== undefined && directory.outcome === "verified") {
    const detail = directory.detail ?? "";
    lines.push(
      detail === "no active keys"
        ? "No active signing keys."
        : `${detail.charAt(0).toUpperCase()}${detail.slice(1)} published.`,
    );
  }
  const signature = verification.check("request.signature");
  if (signature !== undefined) lines.push(signatureLine(signature));
  return lines;
}

function statusLine(v: Verification): string {
  if (v.status === UNKNOWN) return `No identity is published at ${v.subject}.`;
  if (v.status === UNREACHABLE) {
    const fetched = v.check("document.fetched");
    const why = fetched?.detail ? ` (${fetched.detail})` : "";
    return `${v.subject} could not be read${why}.`;
  }
  if (v.status === "suspended") return `${v.subject} is suspended.`;
  return `${v.subject} is ${v.status}, as published by ${v.provider}.`;
}

function ownerLine(c: Check): string | null {
  const kind = c.name.replace(/^owner\./, "");
  const detail = c.detail ?? "";
  if (kind === "standing") {
    if (c.outcome === "verified" && detail)
      return `${detail.charAt(0).toUpperCase()}${detail.slice(1)}.`;
    return null;
  }
  if (c.outcome === "absent") return null;
  const when = c.verified_at ? `, checked ${day(c.verified_at)}` : "";
  let until = "";
  if (c.expires_at) {
    until =
      c.outcome === "invalid" && detail.includes("expired")
        ? `, expired ${day(c.expires_at)}`
        : `, renews ${day(c.expires_at)}`;
  }
  if (kind === "domain") {
    const subject = detail.startsWith("controls")
      ? detail.split(",")[0]!.trim()
      : "";
    if (c.outcome === "invalid" && !subject)
      return `A domain check could not be read (${detail}).`;
    const domain = subject.replace(/^controls /, "").trim();
    const what = domain ? `the domain name ${domain}` : "a domain name";
    return `Owner controls ${what}${when}${until}.`;
  }
  if (kind === "email") {
    const d = c.verified_at ? ` ${day(c.verified_at)}` : "";
    return `Owner's email address was checked${d}${until}.`;
  }
  if (kind === "github") {
    const login = detail.startsWith("controls")
      ? detail
          .split(",")[0]!
          .trim()
          .replace(/^controls /, "")
      : "";
    if (!login) return `A GitHub check could not be read (${detail}).`;
    return `Owner controls the GitHub account @${login}${when}${until}.`;
  }
  if (kind === "person") return personLine(c);
  return `Owner check '${kind}'${when}${until}.`;
}

function signatureLine(c: Check): string {
  const detail = c.detail ?? "";
  if (c.outcome === "verified")
    return `The request was signed with a published key (${detail}).`;
  if (c.outcome === "invalid")
    return `The request's signature does not verify (${detail}).`;
  return `The request's signature could not be checked (${detail}).`;
}

function day(stamp: string | undefined): string {
  return (stamp ?? "").slice(0, 10);
}

/** What a person check's `method` says was looked at. */
const PERSON_METHODS: Record<string, string> = {
  "document-selfie": "Owner's identity document and selfie were checked",
  document: "Owner's identity document was checked",
};

/** A document check is not renewed, so it is "valid until", never
 * "renews"; and it names no one. Mirrors the Python `_person_line`. */
function personLine(c: Check): string {
  const detail = c.detail ?? "";
  const parts = detail
    .split(";")[0]!
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (c.outcome === "invalid" && !c.verified_at)
    return `A person check could not be read (${detail}).`;
  const method = parts.find((p) => !p.startsWith("by ")) ?? "";
  const verifier = (parts.find((p) => p.startsWith("by ")) ?? "").replace(/^by /, "");
  const lead = PERSON_METHODS[method] ?? "A person check was made for the owner";
  const by = verifier ? ` by ${verifier}` : "";
  const on = c.verified_at ? ` on ${day(c.verified_at)}` : "";
  let until = "";
  if (c.expires_at) {
    until =
      c.outcome === "invalid" && detail.includes("expired")
        ? `, expired ${day(c.expires_at)}`
        : `, valid until ${day(c.expires_at)}`;
  }
  return `${lead}${by}${on}${until}.`;
}
