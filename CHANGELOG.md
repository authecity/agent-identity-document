# Changelog

## 2026-10-23 (the `person` check type)

- `spec/`: the owner block defines a fourth check type, `person` (the party
  named in `verifier` checked a government identity document presented for
  the account, with a matching selfie where `method` is `document-selfie`).
  It has no `value`: no name or other attribute of the person is published,
  nor the vendor's identifier for the check. `expires_at` is fixed, the
  check is not renewed in place, and it says nothing about other accounts.
  The privacy considerations say so. No schema change.
- `tests/`: a fixture with a `person` check, and its expected result.
- `python/`, `typescript/`: `summarise` words a `person` check as "Owner's
  identity document and selfie were checked by stripe on …, valid until …".
  The check itself was already reported as `owner.person`.

## 2026-10-23 (wording)

- `python/`, `typescript/`: `summarise` words a domain check as "Owner
  controls the domain name acme.example, …", parallel to the GitHub line,
  so a reader new to DNS is not left to guess what `acme.example` is.
  The spec's example sentence says the same. Expected results regenerated.

## 2026-10-23 (the `github` check type)

- `spec/`: the owner block defines a third check type, `github` (the
  account holder authorized the provider as that GitHub account; `value`
  is the login as last read, `method` is `oauth`), and the privacy
  considerations say what it publishes. No schema change: `type` was
  already an open string, and unknown types were already ignored.
- `tests/`: a fixture with a `github` check, and its expected result.
- `python/`, `typescript/`: `summarise` words a `github` check as "Owner
  controls the GitHub account @login, checked …". The check itself was
  already reported as `owner.github`.

## 2026-10-14 (integrations)

- `integrations/`: three worked examples that refuse unverified agents and
  name the check that failed: a FastAPI dependency
  (`knownas_identity("owner.domain")`), an Express middleware
  (`knownasVerify({ require: ["owner.domain"] })`), and a stateless
  Streamable HTTP MCP server behind that middleware, so an unverified agent
  never reaches a tool. Each has offline tests; a workflow runs them.
- `python/`: `knownas_verify.testing` (`sign_request`, `recorded_provider`,
  `minimal_document`, `TEST_KEY`) for testing code that verifies agents;
  the interop run uses it. The test-only signer file is gone.

## 2026-10-14 (verifier library, TypeScript)

- `typescript/`: `@knownas/verify` 0.1.0, the TypeScript and Node twin of
  `knownas-verify`: `verifyIdentity`, `verifyRequest`, `require`,
  `assertVerified`, `summarise`, the same fetch limits, the same Structured
  Fields subset, Ed25519 through WebCrypto, the schema bundled at
  `v1.0.1-draft`. Its suite reproduces every file in `tests/expected` byte
  for byte and verifies the draft's E.2 vectors with byte-identical
  signature bases. One dependency, `ajv`.
- `python/`: the `document.schema` detail no longer quotes the validator's
  message (validators word them differently); it names the schema and tag.
  `tests/expected` regenerated for that one line.
- A workflow runs the TypeScript package on Node 22 and 24.

## 2026-10-14 (verifier library, signed requests)

- `python/`: `verify_request(request)` verifies one Web Bot Auth signature
  (RFC 9421 under `draft-ietf-webbotauth-httpsig-protocol-00`, the revision
  the reference implementation pins) and then reads the signer's identity.
  Key lookup by the (URL, key) pair from the directory of the covered
  `Signature-Agent` member; required `created`, `expires`, `keyid` and
  `tag`; `kid` recomputed as the JWK thumbprint; discovery failure is
  `unverified`; published test keys refused unless testing; Ed25519 only.
  A strict Structured Fields subset (`sf.py`) replaces a dependency;
  `cryptography` is added for Ed25519.
- `tests/vectors/web-bot-auth-httpsig-00.json`: the draft's Appendix E.2
  vectors as shared test data (signature bases match byte for byte).

## 2026-10-14 (verifier library, lookup)

- `python/`: `knownas-verify` 0.1.0, the verifier library's lookup half.
  `verify_identity(hostname)` reads the document, validates it against the
  schema at `v1.0.1-draft`, reports each owner check with its dates, reads
  the Web Bot Auth key directory, and reports the provider's signed statement
  as absent until providers serve one. Four outcomes per check (`verified`,
  `invalid`, `unverified`, `absent`); `status` is the document's own, or
  `unknown` (a 404) or `unreachable`. No trust flag. `require()` and
  `summarise()` as the reference implementation's ADR 0049 describes.
  Fetches are HTTPS only, bounded, follow no redirects and refuse non-public
  addresses. `verify_request` (signed requests) follows in the next release.
- `tests/fixtures` and `tests/expected`: eight recorded cases every
  implementation must reproduce.
- A GitHub Actions workflow runs the package's lint, type check and tests on
  Python 3.11 to 3.13.

## 2026-10-09 (draft -01)

- `endpoints` lists a service only while the provider routes it to a live
  origin; a reserved but unrouted service hostname is not listed. Follows the
  reference implementation's ADR 0041 (live since 2026-10-07). The `-00`
  text says "one member per service hostname the identity owns".
- The draft source is renamed `-01` and gains a "Changes since -00"
  appendix. The README names the `web-bot-auth@ietf.org` list and the IANA
  registry's GitHub issues.

## 2026-10-03

- First public text of version 1, derived from the knownAs.dev reference
  implementation: the document's members, the suspended form, the `owner`
  block with itemised checks, lifecycle status, provider practices, and the
  relationship to A2A agent cards, Web Bot Auth and ANS.
- JSON Schema (2020-12) and two examples.
- Internet-Draft source, `draft-alla-agent-identity-document-00`, not yet
  submitted.
- Proposes the well-known suffix `agent-identity.json`; the reference
  implementation still serves `agent.json` and will serve both during a
  transition.
