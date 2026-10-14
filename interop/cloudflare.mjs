// Interop run against Cloudflare's open-source verifier (npm `web-bot-auth`).
//
// Three things, each printed as one line of JSON so the Python side and a
// person can read them:
//
//   node cloudflare.mjs vectors            verify the draft's E.2 vectors with web-bot-auth
//   node cloudflare.mjs sign  > out.json   sign a fresh request with the RFC 9421 test key
//   node cloudflare.mjs verify < in.json   verify a request the knownAs signer produced
//
// A request on stdin/stdout is {"method","url","headers":[[name,value],...]}.
// The RFC 9421 test key is used on purpose (the draft's vectors use it); it
// never leaves test code.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sign, verify, generateNonce, jwkToKeyID } from "web-bot-auth";
import { signerFromJWK, verifierFromJWK } from "web-bot-auth/crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(
  readFileSync(join(HERE, "..", "tests", "vectors", "web-bot-auth-httpsig-00.json"), "utf8"),
);
const DIRECTORY = JSON.parse(VECTORS.directory.body);
const PUBLIC_JWK = DIRECTORY.keys[0];
const PRIVATE_JWK = { ...PUBLIC_JWK, alg: "EdDSA", d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" };

function toRequest(r) {
  const headers = new Headers();
  for (const [name, value] of r.headers) headers.append(name, value);
  return new Request(r.url, { method: r.method, headers });
}

function fromRequest(request) {
  const headers = [];
  for (const [name, value] of request.headers) headers.push([name, value]);
  return { method: request.method, url: request.url, headers };
}

async function verifyWith(request, now) {
  const verifier = await verifierFromJWK(PUBLIC_JWK);
  try {
    const result = await verify(request, {
      resolver: (candidate) => {
        if (candidate.keyid !== verifier.keyid) throw new Error(`unknown keyid ${candidate.keyid}`);
        return verifier;
      },
      now,
      maxAge: 10 * 365 * 86400, // the vectors are dated 2025-01-01; age is not what this run tests
    });
    return {
      outcome: "verified",
      label: result.label,
      keyid: result.keyid,
      signatureAgent: result.signatureAgent,
      expires: result.expires.toISOString(),
    };
  } catch (error) {
    return { outcome: "rejected", error: String(error?.message ?? error), code: error?.code };
  }
}

const mode = process.argv[2];

if (mode === "vectors") {
  for (const c of VECTORS.cases) {
    const source = c.request_from ? VECTORS.cases.find((x) => x.name === c.request_from) : c;
    const result = await verifyWith(toRequest(source.request), new Date(c.now));
    console.log(JSON.stringify({ case: c.name, expected: c.expected["request.signature"], cloudflare: result }));
  }
} else if (mode === "sign") {
  const url = process.argv[3] ?? "https://api.example/orders?x=1";
  const agent = process.argv[4] ?? "https://signature-agent.test";
  const legacy = process.argv.includes("--legacy");
  const label = "sig1";
  const signatureAgent = legacy ? `"${agent}"` : `${label}="${agent}";type=directory`;
  const request = new Request(url, { method: "GET", headers: { "Signature-Agent": signatureAgent } });
  const now = new Date();
  const fields = await sign(request, {
    signer: await signerFromJWK(PRIVATE_JWK),
    label,
    created: now,
    expires: new Date(now.getTime() + 300_000),
    nonce: generateNonce(),
    additionalComponents: ["@method"],
  });
  const signed = new Request(url, {
    method: "GET",
    headers: {
      "Signature-Agent": signatureAgent,
      "Signature-Input": fields.signatureInput,
      Signature: fields.signature,
    },
  });
  console.log(JSON.stringify(fromRequest(signed)));
} else if (mode === "verify") {
  const input = JSON.parse(readFileSync(0, "utf8"));
  const result = await verifyWith(toRequest(input), new Date());
  console.log(JSON.stringify({ cloudflare: result, keyid_expected: jwkToKeyID ? undefined : undefined }));
} else {
  console.error("usage: node cloudflare.mjs vectors | sign [url] [agent] [--legacy] | verify < request.json");
  process.exit(2);
}
