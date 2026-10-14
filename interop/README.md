# Interop: `knownas-verify` against Cloudflare's `web-bot-auth`

A reproducible run of the two verifiers over the same signatures, kept here
so anyone can repeat it. Both implement HTTP Message Signatures (RFC 9421)
under the Web Bot Auth profile; this run pins
`draft-ietf-webbotauth-httpsig-protocol-00` (the revision `knownas-verify`
follows) and npm `web-bot-auth` 0.2.0 (`package.json`), which cites
`draft-meunier-webbotauth-httpsig-protocol-00`, the individual draft the
working-group document replaced.

## Run it

```bash
cd interop
npm ci                                   # web-bot-auth 0.2.0 and its three dependencies
python -m venv ../python/.venv && ../python/.venv/Scripts/pip install -e "../python[dev]"
export PYTHONPATH=../python/tests        # the test-only signer

node cloudflare.mjs vectors              # 1. Cloudflare verifies the draft's E.2 vectors
python knownas.py sign | node cloudflare.mjs verify            # 2. knownAs signs, Cloudflare verifies
python knownas.py sign --legacy | node cloudflare.mjs verify   # 3. same, legacy Signature-Agent form
python knownas.py sign --no-alg | node cloudflare.mjs verify   # 4. same, without the optional alg
node cloudflare.mjs sign | python knownas.py verify            # 5. Cloudflare signs, knownAs verifies
node cloudflare.mjs sign https://api.example/o https://signature-agent.test --legacy | python knownas.py verify
```

`knownas-verify`'s own run over the vectors is `python/tests/test_signatures.py`
(signature bases byte for byte, then both signatures). The signer on the
knownAs side is `python/tests/signer.py`, test-only; the platform's SDK will
sign under its ADR 0039 increment 2.

## Result, 2026-10-14

| # | Signer | Verifier | Signature-Agent form | Outcome |
|---|---|---|---|---|
| 1a | draft E.2.1 | Cloudflare | dictionary | verified |
| 1b | draft E.2.2 | Cloudflare | legacy string | verified |
| 1c | draft E.2.2 after expiry | Cloudflare | legacy string | rejected, "Signature has expired" (agrees with knownAs: `invalid`) |
| 2 | knownAs | Cloudflare | dictionary | verified |
| 3 | knownAs | Cloudflare | legacy string | verified |
| 4 | knownAs, no `alg` | Cloudflare | dictionary | **rejected, "Required parameter alg is absent"** |
| 4' | knownAs, no `alg` | knownAs | dictionary | verified |
| 5 | Cloudflare | knownAs | dictionary | verified |
| 6 | Cloudflare | knownAs | legacy string | verified |
| 7 | Cloudflare | Cloudflare | both | verified |

Every signature either implementation produces, the other verifies, and both
read the same `keyid`, the same Signature-Agent member and the same expiry.
`knownas-verify` also verifies the draft's two vectors (its test suite).

## The one divergence

Cloudflare's `verify` requires the `alg` signature parameter
(`requiredParameters: ["created", "expires", "keyid", "alg", "tag"]`,
`packages/web-bot-auth/src/index.ts`). The working-group draft's section 5.2
requires `created`, `expires`, `keyid` and `tag`; `alg` is optional under
RFC 9421 section 3.1, where a verifier may take the algorithm from the key it
resolved. The draft's own vectors carry `alg`, so they pass both; a signer
that follows the draft's MUST list and omits `alg` is rejected by Cloudflare
and accepted by knownAs.

Which side should move is a question for the working group, not a bug in
either: if `alg` is meant to be mandatory for Web Bot Auth, the draft's
section 5.2 should list it; if not, the verifier should derive it from the
resolved key, which it already knows. The reference implementation's owner
raises it upstream (an issue on `cloudflare/web-bot-auth` and a note to the
list), as the project's standards practice requires, and this file records
the answer when it comes.

What `knownas-verify` does meanwhile: accepts a signature without `alg`,
checks `alg` when present and refuses anything but `ed25519`. Signers that
want to verify everywhere should send `alg`, which the knownAs signer does
by default.

## What was not tested

Verification of RSA-PSS signatures (knownAs reads Ed25519 only); the
directory response signature of Appendix B (neither side fetches a directory
in this run: Cloudflare's verifier takes a resolver, knownAs's run uses a
recorded directory); `@query-param`, which Cloudflare's `http-message-sig`
rejects as unsupported and knownAs supports.
