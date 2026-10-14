// An unsigned caller never reaches the MCP server; a verified one initialises
// and calls a tool. Runs without a network (recorded provider, the draft's
// E.2.1 vector, RFC 9421's test key accepted only because the test says so).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { Fetched, RecordedFetcher } from "@knownas/verify";
import { makeApp } from "./server.ts";

const VECTORS = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../tests/vectors/web-bot-auth-httpsig-00.json", import.meta.url)), "utf8"),
);
const E21 = VECTORS.cases[0];
const AGENT = "signature-agent.test";
const NOW = new Date(E21.now);

const DOCUMENT = {
  version: "1",
  name: "Test agent",
  status: "active",
  fqdn: AGENT,
  endpoints: { web: `https://${AGENT}`, manifest: `https://${AGENT}/.well-known/agent-identity.json` },
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

const json = (status: number, body: object) =>
  new Fetched(status, { "content-type": "application/json" }, new TextEncoder().encode(JSON.stringify(body)));
const fetcher = new RecordedFetcher(
  new Map([
    [`https://${AGENT}/.well-known/agent-identity.json`, json(200, DOCUMENT)],
    [
      VECTORS.directory.url,
      new Fetched(200, { "content-type": VECTORS.directory.content_type }, new TextEncoder().encode(VECTORS.directory.body)),
    ],
    [`https://${AGENT}/.well-known/agent-identity-statement.jws`, json(404, { error: "not_found" })],
  ]),
);

// Some desktop security suites intercept loopback HTTP on paths ending in
// /mcp and corrupt the response framing (seen with Avast on Windows). Set
// MCP_TEST_PATH=/rpc to run the tests past such a proxy; CI uses /mcp.
const PATH = process.env["MCP_TEST_PATH"] ?? "/mcp";
const app = makeApp({ require: ["owner.domain"], fetcher, now: () => NOW, allowTestKeys: true }, PATH);
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

function post(path: string, headers: Record<string, string>, body: object): Promise<{ status: number; body: string }> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          ...headers,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (text += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/** The vector's signature headers (signed over @authority = example.com and
 * the Signature-Agent member only, so any method and path verify). */
function signedHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of E21.request.headers as [string, string][]) headers[name] = value;
  return headers;
}

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "0" } },
};

/** The body of a JSON-RPC result, whether the transport answered JSON or SSE. */
function resultOf(body: string): Record<string, unknown> {
  const line = body.split("\n").find((l) => l.startsWith("data:"));
  const text = line ? line.slice("data:".length).trim() : body;
  return JSON.parse(text) as Record<string, unknown>;
}

test("an unsigned initialize is refused with 401 before any JSON-RPC is read", async () => {
  const reply = await post(PATH, { Host: "example.com" }, INITIALIZE);
  assert.equal(reply.status, 401);
  assert.equal(JSON.parse(reply.body).check, "request.signature");
});

test("a signed, verified caller initialises and calls a tool", async () => {
  const init = await post(PATH, signedHeaders(), INITIALIZE);
  assert.equal(init.status, 200, init.body);
  const initResult = resultOf(init.body);
  assert.equal((initResult["result"] as { serverInfo: { name: string } }).serverInfo.name, "orders-for-named-agents");

  const call = await post(PATH, signedHeaders(), {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "whoami", arguments: {} },
  });
  assert.equal(call.status, 200, call.body);
  const text = ((resultOf(call.body)["result"] as { content: { text: string }[] }).content[0] ?? { text: "" }).text;
  assert.ok(text.includes(`Calling agent: ${AGENT}`), text);
  assert.ok(text.includes("Owner controls acme.example, checked 2026-10-02, renews 2026-11-01."), text);
});
