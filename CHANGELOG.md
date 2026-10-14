# Changelog

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
