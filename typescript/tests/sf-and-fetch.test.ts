// The Structured Fields subset (RFC 8941's own examples) and the fetcher's limits.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CachingFetcher, FetchError, Fetched, RecordedFetcher, USER_AGENT, checkSubject, isGlobal } from "../src/fetch.ts";
import * as sf from "../src/sf.ts";

test("dictionary with items, inner lists and parameters; RFC 9421 2.1.2 member values", () => {
  const d = sf.parseDictionary("a=1, b=2;x=1;y=2, c=(a   b    c), d");
  assert.equal(sf.serializeMember(d.get("a")!), "1");
  assert.equal(sf.serializeMember(d.get("d")!), "?1");
  assert.equal(sf.serializeMember(d.get("b")!), "2;x=1;y=2");
  assert.equal(sf.serializeMember(d.get("c")!), "(a b c)");
});

test("Signature-Input round-trips byte for byte", () => {
  const text =
    'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p4/33+xm==";tag="web-bot-auth"';
  const inner = sf.parseDictionary(text).get("sig2")!;
  assert.equal(inner.kind, "inner-list");
  if (inner.kind === "inner-list") {
    assert.equal(sf.serializeInnerList(inner), text.slice("sig2=".length));
    assert.equal(inner.params.get("created"), 1735689600);
    assert.equal(inner.items[1]!.params.get("key"), "agent2");
  }
});

test("bare item types", () => {
  assert.equal(sf.parseItem('"a \\"quoted\\" \\\\ string"').value, 'a "quoted" \\ string');
  assert.deepEqual(sf.parseItem(":AQID:").value, new Uint8Array([1, 2, 3]));
  assert.equal(sf.parseItem("?0").value, false);
  assert.equal(sf.serializeBareItem(new sf.Decimal(4.5)), "4.5");
  assert.equal(sf.serializeBareItem(new sf.Decimal(1)), "1.0");
  assert.equal(sf.serializeBareItem(new Uint8Array([1, 2, 3])), ":AQID:");
  assert.equal(sf.serializeBareItem(new sf.Token("web-bot-auth")), "web-bot-auth");
  assert.equal(sf.serializeBareItem("web-bot-auth"), '"web-bot-auth"');
});

test("malformed input throws", () => {
  for (const bad of ["a=", "a=1,", '"unterminated', "a=(1 2", "a=1;;b", "A=1", ":not base64!:", "?2", "a=1 b=2"]) {
    assert.throws(() => sf.parseDictionary(bad), sf.SFError, bad);
  }
  assert.throws(() => sf.serializeBareItem("café"), sf.SFError);
});

test("checkSubject normalises and refuses", () => {
  assert.equal(checkSubject(" Alice.KnownAs.dev. "), "alice.knownas.dev");
  for (const bad of ["", "localhost", "127.0.0.1", "[::1]", "2001:db8::1", "a..b", "-a.b", "a_b.c"]) {
    assert.throws(() => checkSubject(bad), (e: unknown) => e instanceof FetchError && e.kind === "refused", bad);
  }
});

test("isGlobal covers every special-purpose range", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "169.254.1.1", "100.64.0.1", "192.168.1.1", "172.16.0.1", "0.0.0.0", "224.0.0.1", "::1", "fd00::1", "fe80::1", "::"]) {
    assert.equal(isGlobal(ip), false, ip);
  }
  for (const ip of ["93.184.216.34", "1.1.1.1", "2606:4700::1111"]) assert.equal(isGlobal(ip), true, ip);
});

test("the recorded fetcher enforces the byte limit", async () => {
  const f = new RecordedFetcher(new Map([["https://a.example/x", new Fetched(200, {}, new Uint8Array(100))]]));
  await assert.rejects(
    f.get("https://a.example/x", { accept: "*/*", maxBytes: 10, timeout: 1 }),
    (e: unknown) => e instanceof FetchError && e.kind === "too_large",
  );
});

test("caching honours max-age up to the cap and never caches failures", async () => {
  let now = 0;
  const url = "https://a.example/.well-known/agent-identity.json";
  const served = new Fetched(200, { "cache-control": "max-age=86400" }, new TextEncoder().encode("{}"));
  const inner = new RecordedFetcher(new Map([[url, served]]));
  const cache = new CachingFetcher(inner, { "/.well-known/agent-identity.json": 60 }, () => now);
  await cache.get(url, { accept: "*/*", maxBytes: 100, timeout: 1 });
  await cache.get(url, { accept: "*/*", maxBytes: 100, timeout: 1 });
  assert.deepEqual(inner.calls, [url]);
  now = 61;
  await cache.get(url, { accept: "*/*", maxBytes: 100, timeout: 1 });
  assert.deepEqual(inner.calls, [url, url]);

  const failing = new RecordedFetcher(new Map([["https://b.example/x", new FetchError("network", "down")]]));
  const cache2 = new CachingFetcher(failing, { "/x": 60 }, () => 0);
  for (let i = 0; i < 2; i += 1) {
    await assert.rejects(cache2.get("https://b.example/x", { accept: "*/*", maxBytes: 100, timeout: 1 }));
  }
  assert.equal(failing.calls.length, 2);
});

test("the user agent names the library and nothing else", () => {
  assert.ok(USER_AGENT.startsWith("knownas-verify/"));
  assert.ok(USER_AGENT.includes("github.com/authecity/agent-identity-document"));
});
