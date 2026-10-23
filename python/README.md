# knownas-verify

Read an AI agent's public identity and get back **what was checked**, as a
list of dated checks. There is no trust flag, score or level, and no function
that returns one. The relying party decides, by naming the checks it depends
on.

```python
from knownas_verify import verify_identity, require, summarise

v = verify_identity("alice.knownas.dev")

v.status
# 'active', 'suspended', 'pending', ... or 'unknown' / 'unreachable'

v.check("owner.domain")
# Check(name='owner.domain', outcome='verified',
#       detail='controls acme.example, dns-txt, by knownas.dev',
#       verified_at='2026-10-02T09:00:00+00:00', expires_at='2026-11-01T09:00:00+00:00')

if require(v, "document.schema", "owner.domain"):
    ...  # the two facts this code rests on, by name

for line in summarise(v):
    print(line)
# alice.knownas.dev is active, as published by knownas.dev.
# Owner's email address was checked 2026-09-21.
# Owner controls the domain name acme.example, checked 2026-10-02, renews 2026-11-01.
# Account since 2026-09-21, active.
# 2 active keys published.
```

## What it reads

All of it public, all served by the identity's own host over HTTPS:

| Check | Record |
|---|---|
| `document.fetched`, `document.schema`, `document.host` | The [Agent Identity Document](../spec/agent-identity-document.md) at `/.well-known/agent-identity.json`, validated against the specification's JSON Schema at the tag this package bundles |
| `owner.<type>` (one per published check), `owner.standing` | The document's `owner` block: itemised, dated, expiring checks, and the account's standing |
| `keys.directory` | The Web Bot Auth key directory at `/.well-known/http-message-signatures-directory` |
| `platform.statement` | The provider's signed statement about the document, reported `absent` until providers serve one |

It never reads a status file or badge that summarises the document, never
reads the A2A agent card, and never connects to the agent's endpoints.

## Signed requests

`verify_request` checks an HTTP request signed under Web Bot Auth (HTTP
Message Signatures, RFC 9421, as profiled by
`draft-ietf-webbotauth-httpsig-protocol-00`), then reads the signer's
identity as above:

```python
from knownas_verify import Request, verify_request, require

request = Request.from_mapping(
    method="GET",
    url="https://api.example/orders",          # the target URI you served
    headers={"Signature-Agent": ..., "Signature-Input": ..., "Signature": ...},
)
v = verify_request(request)

v.check("request.agent")       # which Signature-Agent member the signature covers
v.check("request.signature")   # verified | invalid | unverified, with the label, key and covered components
require(v, "request.signature", "owner.domain")
```

What it makes binding: the key is looked up by the **(URL, key) pair**, from
the directory of the `Signature-Agent` member the signature covers, never by
key alone; `created`, `expires`, `keyid` and `tag="web-bot-auth"` are
required and `expires` is enforced by your clock; the directory's `kid` must
be the key's own thumbprint; a discovery failure is `unverified`, never
`invalid`; published test keys are refused unless you pass
`allow_test_keys=True` in a test. Only Ed25519 keys are read. The signature
base is built per RFC 9421 section 2.5 and matches the draft's Appendix E.2
vectors byte for byte (`../tests/vectors`).

## Outcomes

Each check has one of four outcomes:

- `verified`: the record says it, and it holds now;
- `invalid`: the record says it, and it does not hold (an expired check, a
  document naming another host, a malformed directory);
- `unverified`: the library could not obtain enough to decide (a fetch
  failed, a redirect was refused). Never treated as `invalid` or `verified`;
- `absent`: the record does not carry it.

`status` is the document's own `status`, or `unknown` when the host answers
404 (the specification's "no identity is published here"), or `unreachable`
when nothing readable came back. The two are never merged: the first is a
statement by the provider, the second is not.

## Limits the library applies

Fetches are HTTPS only, follow no redirects, refuse private, loopback and
link-local addresses, read at most 64 kB and wait at most 5 seconds. Caching
honours `Cache-Control: max-age` up to the provider's own lifetimes (60 s for
the document, 300 s for the directory), so a removed key stops verifying
within that bound and not before; the library does not promise instant
revocation.

## Install

```bash
pip install knownas-verify
```

Python 3.11 or later. Two dependencies: `jsonschema` and `cryptography`.

## Tests

The fixtures in [`../tests/fixtures`](../tests/fixtures) are recorded responses
shared by every implementation of this library; [`../tests/expected`](../tests/expected)
holds the result each must produce. Run with:

```bash
cd python
python -m pip install -e ".[dev]"
pytest
```

A live read against the knownAs.dev development environment is opt-in:
`KNOWNAS_VERIFY_LIVE_SUBJECT=<identity hostname> pytest -m live`.

## Licence

Apache-2.0, like the schema. The specification's prose is CC BY 4.0.
