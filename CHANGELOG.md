# Changelog

## Unreleased (will be draft -01)

- `endpoints` lists a service only while the provider routes it to a live
  origin; a reserved but unrouted service hostname is not listed. Follows the
  reference implementation's ADR 0041 (proposed 2026-10-03). The submitted
  `-00` text says "one member per service hostname the identity owns"; the
  readable spec and the draft source here already carry the new rule.

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
