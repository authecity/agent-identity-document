// Every recorded fixture produces exactly the expected result the Python
// implementation produced; the two are one contract.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { FORBIDDEN_WORDS, summarise, verifyIdentity } from "../src/index.ts";
import { SCHEMA_URL } from "../src/identity.ts";
import { REPO, fixtureClock, fixtureNames, loadExpected, loadFixture, recorded } from "./helpers.ts";

for (const name of fixtureNames()) {
  test(`fixture ${name} matches tests/expected/${name}.json`, async () => {
    const fixture = loadFixture(name);
    const fetcher = recorded(fixture);
    const v = await verifyIdentity(fixture.subject, { fetcher, now: fixtureClock(fixture) });
    const actual = JSON.parse(JSON.stringify({ verification: v, summary: summarise(v) }));
    assert.deepEqual(actual, loadExpected(name));
    const host = fixture.subject;
    for (const url of fetcher.calls) {
      assert.ok(
        [
          `https://${host}/.well-known/agent-identity.json`,
          `https://${host}/.well-known/http-message-signatures-directory`,
          `https://${host}/.well-known/agent-identity-statement.jws`,
        ].includes(url),
        `unexpected fetch ${url}`,
      );
    }
  });

  test(`fixture ${name}: no forbidden word, no trust field`, async () => {
    const fixture = loadFixture(name);
    const v = await verifyIdentity(fixture.subject, { fetcher: recorded(fixture), now: fixtureClock(fixture) });
    const text = summarise(v).join(" ").toLowerCase();
    for (const word of FORBIDDEN_WORDS) assert.ok(!text.includes(word), `${word} in ${text}`);
    const flat = JSON.stringify(v).toLowerCase();
    for (const field of ['"trusted"', '"score"', '"level"', '"ok"']) assert.ok(!flat.includes(field));
    for (const c of v.checks) assert.ok(["verified", "invalid", "unverified", "absent"].includes(c.outcome));
  });
}

test("the bundled schema is the repository's schema", () => {
  const bundled = JSON.parse(readFileSync(SCHEMA_URL, "utf8"));
  const root = JSON.parse(readFileSync(`${REPO}schema/agent-identity-document.schema.json`, "utf8"));
  assert.deepEqual(bundled, root);
});
