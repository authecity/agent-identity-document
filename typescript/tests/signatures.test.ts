// Signed requests: the draft's Ed25519 vectors, and the rules around them.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { FetchError, Fetched, RecordedFetcher } from "../src/fetch.ts";
import { Request, jwkThumbprint, require, signatureBase, summarise, verifyRequest } from "../src/index.ts";
import { parseDictionary } from "../src/sf.ts";
import { VECTORS } from "./helpers.ts";

interface Case {
  name: string;
  now: string;
  request?: { method: string; url: string; headers: [string, string][] };
  request_from?: string;
  signature_base?: string;
  expected: Record<string, string>;
}
const vectors = JSON.parse(readFileSync(`${VECTORS}web-bot-auth-httpsig-00.json`, "utf8")) as {
  directory: { url: string; content_type: string; body: string };
  cases: Case[];
};
const DIRECTORY_URL = vectors.directory.url;
const DIRECTORY = new Fetched(
  200,
  { "content-type": vectors.directory.content_type, "cache-control": "max-age=300" },
  new TextEncoder().encode(vectors.directory.body),
);
const AGENT_DOC = new Fetched(
  200,
  { "content-type": "application/json", "access-control-allow-origin": "*" },
  new TextEncoder().encode(
    JSON.stringify({
      version: "1",
      name: "Test agent",
      status: "active",
      fqdn: "signature-agent.test",
      endpoints: {
        web: "https://signature-agent.test",
        manifest: "https://signature-agent.test/.well-known/agent-identity.json",
      },
    }),
  ),
);
const NOT_FOUND = new Fetched(404, { "content-type": "application/json" }, new TextEncoder().encode('{"error":"not_found"}'));

function caseNamed(name: string): Case {
  const c = vectors.cases.find((x) => x.name === name);
  if (!c) throw new Error(name);
  return c;
}

function requestOf(c: Case): Request {
  const source = c.request_from ? caseNamed(c.request_from) : c;
  const r = source.request!;
  return new Request(r.method, r.url, r.headers);
}

function fetcher(overrides: Record<string, Fetched | FetchError> = {}): RecordedFetcher {
  const responses = new Map<string, Fetched | FetchError>([
    [DIRECTORY_URL, DIRECTORY],
    ["https://signature-agent.test/.well-known/agent-identity.json", AGENT_DOC],
    ["https://signature-agent.test/.well-known/agent-identity-statement.jws", NOT_FOUND],
  ]);
  for (const [k, v] of Object.entries(overrides)) responses.set(k, v);
  return new RecordedFetcher(responses);
}

function withHeader(r: Request, name: string, value: string): Request {
  return new Request(
    r.method,
    r.url,
    r.headers.map(([n, v]) => (n.toLowerCase() === name.toLowerCase() ? [n, value] : [n, v])),
  );
}

test("the test key's thumbprint is the draft's kid", async () => {
  const key = JSON.parse(vectors.directory.body).keys[0];
  assert.equal(await jwkThumbprint(key), "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
});

for (const c of vectors.cases.filter((x) => x.signature_base !== undefined)) {
  test(`signature base matches the draft: ${c.name}`, () => {
    const request = requestOf(c);
    const inputs = parseDictionary(request.fieldValue("signature-input") ?? "");
    const inner = inputs.get("sig2")!;
    assert.equal(inner.kind, "inner-list");
    if (inner.kind === "inner-list") assert.equal(signatureBase(request, inner), c.signature_base);
  });
}

for (const c of vectors.cases) {
  test(`vector: ${c.name}`, async () => {
    const v = await verifyRequest(requestOf(c), { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
    assert.equal(v.check("request.signature")?.outcome, c.expected["request.signature"]);
    if (c.expected["detail_contains"]) {
      assert.ok(v.check("request.signature")?.detail?.includes(c.expected["detail_contains"]));
    }
    if (c.expected["request.agent"]) {
      assert.equal(v.check("request.agent")?.outcome, c.expected["request.agent"]);
      assert.equal(v.subject, "signature-agent.test");
      assert.equal(v.status, "active");
    }
  });
}

const E21 = "E.2.1 Signature-Agent dictionary member present on the request";

test("a verified request reads the signer's identity and summarises it", async () => {
  const c = caseNamed(E21);
  const v = await verifyRequest(requestOf(c), { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.ok(require(v, "request.signature", "document.schema", "keys.directory"));
  assert.ok(v.check("request.signature")?.detail?.includes("label sig2"));
  assert.ok(v.check("request.signature")?.detail?.includes('covers "@authority" "signature-agent";key="agent2"'));
  const lines = summarise(v);
  assert.equal(lines[0], "signature-agent.test is active, as published by signature-agent.test.");
  assert.ok(lines.some((l) => l.startsWith("The request was signed with a published key")));
});

test("a test key is refused unless the caller is testing", async () => {
  const c = caseNamed(E21);
  const v = await verifyRequest(requestOf(c), { fetcher: fetcher(), now: new Date(c.now) });
  assert.equal(v.check("request.signature")?.outcome, "invalid");
  assert.ok(v.check("request.signature")?.detail?.includes("test key"));
});

test("a tampered signature and a changed authority are invalid", async () => {
  const c = caseNamed(E21);
  const r = requestOf(c);
  const tampered = withHeader(r, "Signature", r.fieldValue("signature")!.replace("RdNFx5Bj6au3", "RdNFx5Bj6au4"));
  const v = await verifyRequest(tampered, { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.equal(v.check("request.signature")?.outcome, "invalid");
  assert.ok(v.check("request.signature")?.detail?.includes("does not verify"));
  const moved = new Request(r.method, "https://evil.example/foo", r.headers);
  const v2 = await verifyRequest(moved, { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.equal(v2.check("request.signature")?.outcome, "invalid");
});

test("discovery failure is unverified, never invalid", async () => {
  const c = caseNamed(E21);
  for (const failure of [NOT_FOUND, new FetchError("timeout", "no answer within 5s")]) {
    const v = await verifyRequest(requestOf(c), {
      fetcher: fetcher({ [DIRECTORY_URL]: failure }),
      now: new Date(c.now),
      allowTestKeys: true,
    });
    assert.equal(v.check("request.signature")?.outcome, "unverified");
    assert.ok(v.check("request.signature")?.detail?.includes("key discovery failed"));
    assert.equal(v.subject, "signature-agent.test");
  }
});

test("an unknown keyid is unverified and a mislabelled key is invalid", async () => {
  const c = caseNamed(E21);
  const other = JSON.parse(vectors.directory.body);
  other.keys[0].kid = "someone-elses-label";
  const mislabelled = new Fetched(200, DIRECTORY.headers, new TextEncoder().encode(JSON.stringify(other)));
  const v = await verifyRequest(requestOf(c), {
    fetcher: fetcher({ [DIRECTORY_URL]: mislabelled }),
    now: new Date(c.now),
    allowTestKeys: true,
  });
  assert.equal(v.check("request.signature")?.outcome, "unverified");
  other.keys[0].kid = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
  other.keys[0].x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
  const swapped = new Fetched(200, DIRECTORY.headers, new TextEncoder().encode(JSON.stringify(other)));
  const v2 = await verifyRequest(requestOf(c), {
    fetcher: fetcher({ [DIRECTORY_URL]: swapped }),
    now: new Date(c.now),
    allowTestKeys: true,
  });
  assert.equal(v2.check("request.signature")?.outcome, "invalid");
  assert.ok(v2.check("request.signature")?.detail?.includes("thumbprint"));
});

test("a signature must cover a Signature-Agent member and carry the tag", async () => {
  const c = caseNamed(E21);
  const r = requestOf(c);
  const uncovered = withHeader(
    r,
    "Signature-Input",
    'sig2=("@authority");created=1735689600;keyid="k";expires=4889289600;tag="web-bot-auth"',
  );
  const v = await verifyRequest(uncovered, { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.equal(v.check("request.signature")?.outcome, "invalid");
  assert.ok(v.check("request.signature")?.detail?.includes("does not cover a Signature-Agent member"));
  assert.equal(v.subject, "");
  const otherTag = withHeader(
    r,
    "Signature-Input",
    'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="k";expires=4889289600;tag="other"',
  );
  const v2 = await verifyRequest(otherTag, { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.equal(v2.check("request.signature")?.outcome, "unverified");
  assert.ok(v2.check("request.signature")?.detail?.includes("no signature carries tag"));
});

test("a non-origin Signature-Agent member is ignored", async () => {
  const c = caseNamed(E21);
  const r = withHeader(requestOf(c), "Signature-Agent", 'agent2="https://signature-agent.test/keys.json"');
  const v = await verifyRequest(r, { fetcher: fetcher(), now: new Date(c.now), allowTestKeys: true });
  assert.equal(v.check("request.signature")?.outcome, "unverified");
  assert.ok(v.check("request.signature")?.detail?.includes("not an https origin"));
});

test("an unsigned request is unverified and touches no network", async () => {
  const f = fetcher();
  const v = await verifyRequest(new Request("GET", "https://example.com/", []), { fetcher: f });
  assert.equal(v.check("request.signature")?.outcome, "unverified");
  assert.deepEqual(f.calls, []);
});

test("derived components", () => {
  const r = new Request("get", "https://Example.com:443/a/b?x=1&y=two%20words", [["Host", "example.com"]]);
  const inputs = parseDictionary(
    'sig=("@method" "@authority" "@scheme" "@path" "@query" "@request-target" "@target-uri" "@query-param";name="y");created=1;expires=2;keyid="k";tag="web-bot-auth"',
  );
  const inner = inputs.get("sig")!;
  assert.equal(inner.kind, "inner-list");
  if (inner.kind !== "inner-list") return;
  const base = signatureBase(r, inner);
  assert.ok(base.includes('"@method": GET'));
  assert.ok(base.includes('"@authority": example.com'));
  assert.ok(base.includes('"@scheme": https'));
  assert.ok(base.includes('"@path": /a/b'));
  assert.ok(base.includes('"@query": ?x=1&y=two%20words'));
  assert.ok(base.includes('"@request-target": /a/b?x=1&y=two%20words'));
  assert.ok(base.includes('"@query-param";name="y": two%20words'));
});
