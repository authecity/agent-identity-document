// The middleware refuses unsigned and under-verified callers and serves the rest.
// Runs without a network: the signer's provider is recorded, and the request
// is the draft's E.2.1 vector (RFC 9421's test key), accepted only because
// the test says allowTestKeys. Requests go through node:http so the Host
// header the signature covers can be set (fetch refuses to set Host).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import express from "express";
import { Fetched, RecordedFetcher } from "@knownas/verify";
import { knownasVerify } from "./knownas.ts";

const VECTORS = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../tests/vectors/web-bot-auth-httpsig-00.json", import.meta.url)), "utf8"),
);
const E21 = VECTORS.cases[0];
const AGENT = "signature-agent.test";
const NOW = new Date(E21.now);

function provider(document: object): RecordedFetcher {
  const json = (status: number, body: object) =>
    new Fetched(status, { "content-type": "application/json" }, new TextEncoder().encode(JSON.stringify(body)));
  return new RecordedFetcher(
    new Map([
      [`https://${AGENT}/.well-known/agent-identity.json`, json(200, document)],
      [
        VECTORS.directory.url,
        new Fetched(
          200,
          { "content-type": VECTORS.directory.content_type },
          new TextEncoder().encode(VECTORS.directory.body),
        ),
      ],
      [`https://${AGENT}/.well-known/agent-identity-statement.jws`, json(404, { error: "not_found" })],
    ]),
  );
}

const BASE_DOCUMENT = {
  version: "1",
  name: "Test agent",
  status: "active",
  fqdn: AGENT,
  endpoints: { web: `https://${AGENT}`, manifest: `https://${AGENT}/.well-known/agent-identity.json` },
};
const WITH_DOMAIN = {
  ...BASE_DOCUMENT,
  owner: {
    verifications: [
      {
        type: "domain",
        value: "acme.example",
        method: "dns-txt",
        verifier: "agents.example",
        verified_at: "2026-10-02T09:00:00+00:00",
        expires_at: "2026-11-01T09:00:00+00:00",
      },
    ],
    standing: { account_since: "2026-09-21", status: "active" },
  },
};

const app = express();
app.get(
  "/foo",
  knownasVerify({ require: ["owner.domain"], fetcher: provider(WITH_DOMAIN), now: () => NOW, allowTestKeys: true }),
  (_req, res) => res.json({ ok: true, agent: res.locals["identity"].subject }),
);
app.get(
  "/no-domain",
  knownasVerify({ require: ["owner.domain"], fetcher: provider(BASE_DOCUMENT), now: () => NOW, allowTestKeys: true }),
  (_req, res) => res.json({ ok: true }),
);

let server: ReturnType<typeof app.listen>;
let port = 0;

before(async () => {
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  port = typeof address === "object" && address ? address.port : 0;
});
after(() => server.close());

interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function get(path: string, headers: Record<string, string>): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

/** The vector's headers, with the Host the signature covers. */
function vectorHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of E21.request.headers as [string, string][]) headers[name] = value;
  return headers;
}

test("an unsigned request is refused with 401", async () => {
  const reply = await get("/foo?param=Value&Pet=dog", { Host: "example.com" });
  assert.equal(reply.status, 401);
  assert.equal(reply.headers["www-authenticate"], 'Signature realm="knownas"');
  const body = JSON.parse(reply.body);
  assert.equal(body.check, "request.signature");
  assert.equal(body.outcome, "unverified");
});

test("the draft's signed request from a verified owner is served", async () => {
  const reply = await get("/foo?param=Value&Pet=dog", vectorHeaders());
  assert.equal(reply.status, 200, reply.body);
  assert.deepEqual(JSON.parse(reply.body), { ok: true, agent: AGENT });
});

test("a signed request whose owner lacks the domain check gets 403 naming it", async () => {
  const reply = await get("/no-domain", vectorHeaders());
  assert.equal(reply.status, 403, reply.body);
  const body = JSON.parse(reply.body);
  assert.equal(body.subject, AGENT);
  assert.equal(body.failed[0].check, "owner.domain");
  assert.equal(body.failed[0].outcome, "absent");
});

test("a signature over another authority is invalid", async () => {
  const headers = vectorHeaders();
  headers["Host"] = "evil.example";
  const reply = await get("/foo", headers);
  assert.equal(reply.status, 401);
  assert.equal(JSON.parse(reply.body).outcome, "invalid");
});
