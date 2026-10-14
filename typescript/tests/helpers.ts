import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { FetchError, Fetched, RecordedFetcher } from "../src/fetch.ts";

export const REPO = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES = `${REPO}tests/fixtures/`;
export const EXPECTED = `${REPO}tests/expected/`;
export const VECTORS = `${REPO}tests/vectors/`;

export interface Fixture {
  subject: string;
  now: string;
  responses: Record<
    string,
    { status: number; headers?: Record<string, string>; body?: unknown } | { error: { kind: string; detail: string } }
  >;
}

export function fixtureNames(): string[] {
  return readdirSync(FIXTURES)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -5))
    .sort();
}

export function loadFixture(name: string): Fixture {
  return JSON.parse(readFileSync(`${FIXTURES}${name}.json`, "utf8")) as Fixture;
}

export function loadExpected(name: string): unknown {
  return JSON.parse(readFileSync(`${EXPECTED}${name}.json`, "utf8"));
}

export function recorded(fixture: Fixture): RecordedFetcher {
  const responses = new Map<string, Fetched | FetchError>();
  for (const [url, spec] of Object.entries(fixture.responses)) {
    if ("error" in spec) {
      responses.set(url, new FetchError(spec.error.kind, spec.error.detail));
      continue;
    }
    const body = spec.body ?? "";
    const raw = new TextEncoder().encode(typeof body === "string" ? body : JSON.stringify(body));
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(spec.headers ?? {})) headers[k.toLowerCase()] = v;
    responses.set(url, new Fetched(spec.status, headers, raw));
  }
  return new RecordedFetcher(responses);
}

export function fixtureClock(fixture: Fixture): Date {
  return new Date(fixture.now);
}
