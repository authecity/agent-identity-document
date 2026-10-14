# @knownas/verify

Read an AI agent's public identity and get back **what was checked**, as a
list of dated checks. There is no trust flag, score or level, and no function
that returns one. The relying party decides, by naming the checks it depends
on. This is the TypeScript twin of the Python package
[`knownas-verify`](../python/); the two share one contract, one set of
recorded fixtures and one expected result for each.

```ts
import { verifyIdentity, require, summarise } from "@knownas/verify";

const v = await verifyIdentity("alice.knownas.dev");

v.status;                     // 'active', 'suspended', 'pending', ... or 'unknown' / 'unreachable'
v.check("owner.domain");      // { name, outcome: 'verified', detail: 'controls acme.example, dns-txt, by knownas.dev', verified_at, expires_at }

if (require(v, "document.schema", "owner.domain")) {
  // the two facts this code rests on, by name
}

for (const line of summarise(v)) console.log(line);
// alice.knownas.dev is active, as published by knownas.dev.
// Owner's email address was checked 2026-09-21.
// Owner controls acme.example, checked 2026-10-02, renews 2026-11-01.
// Account since 2026-09-21, active.
// 2 active keys published.
```

## Signed requests

```ts
import { Request, verifyRequest, require } from "@knownas/verify";

// From a Fetch Request you served (the URL is the target URI as served):
const request = Request.fromHeaders(req.method, req.url, req.headers);
const v = await verifyRequest(request);

v.check("request.agent");      // which Signature-Agent member the signature covers
v.check("request.signature");  // verified | invalid | unverified, with the label, key and covered components
require(v, "request.signature", "owner.domain");
```

`verifyRequest` follows HTTP Message Signatures (RFC 9421) as profiled by
`draft-ietf-webbotauth-httpsig-protocol-00`: the key is looked up by the
**(URL, key) pair** from the directory of the `Signature-Agent` member the
signature covers, never by key alone; `created`, `expires`, `keyid` and
`tag="web-bot-auth"` are required and `expires` is enforced by your clock;
the directory's `kid` must be the key's own thumbprint; a discovery failure
is `unverified`, never `invalid`; published test keys are refused unless you
pass `allowTestKeys: true` in a test. Only Ed25519 keys are read, through
WebCrypto.

## What it reads, outcomes, limits

The same as the Python package: see [its README](../python/README.md). In
short: the document at `/.well-known/agent-identity.json`, the schema at
the tag this package bundles (`schema/`), the owner block, the key directory,
and the provider's signed statement (reported `absent` until providers serve
one). Four outcomes per check: `verified`, `invalid`, `unverified`,
`absent`. `status` is the document's own, or `unknown` (a 404) or
`unreachable`. Fetches are HTTPS only, follow no redirects, refuse
non-public addresses, read at most 64 kB and wait at most 5 seconds;
caching honours `max-age` up to the provider's own lifetimes.

## Install

```bash
npm install @knownas/verify
```

Node 22.12 or later (WebCrypto Ed25519, `fetch`). One dependency, `ajv`.

## Tests

```bash
cd typescript
npm ci
npm run typecheck
npm test            # node --test over tests/*.test.ts, on the shared fixtures, expected results and vectors
```

## Licence

Apache-2.0, like the schema. The specification's prose is CC BY 4.0.
