# The Agent Identity Document

An open specification for a small JSON document that gives an AI agent a
public, checkable identity on the internet: **who it is, who answers for it,
and whether it is still in good standing**, served at a well-known URI on a
hostname that belongs to that one agent.

```text
https://alice.knownas.dev/.well-known/agent-identity.json
```

It is written for agents whose operators **do not run a domain**. An identity
provider hosts the name, the TLS and the document; the operator gets all three
in one request. The format keeps what the provider *knows* (hostname,
endpoints, lifecycle status) apart from what the operator *claims*
(description, contact, homepage), publishes the provider's checks on the
operator as dated, expiring records rather than a badge, and insists that a
person or organisation stands behind every agent.

The reference implementation is [knownAs.dev](https://knownas.dev). The
format is published so that other providers can implement it, relying
parties can depend on it, and it can be mapped onto related work (A2A agent
cards, Web Bot Auth, the Agent Name Service).

## What is here

| Path | What | Licence |
|---|---|---|
| [`spec/agent-identity-document.md`](spec/agent-identity-document.md) | The specification, readable form | CC BY 4.0 |
| [`draft/`](draft/) | The same text as an IETF Internet-Draft (kramdown-rfc source) | IETF Trust provisions apply once submitted |
| [`schema/agent-identity-document.schema.json`](schema/agent-identity-document.schema.json) | JSON Schema (2020-12) for version 1 | Apache-2.0 |
| [`examples/`](examples/) | Valid documents: active, suspended | Apache-2.0 |

Prose is licensed under [CC BY 4.0](LICENSE-CC-BY-4.0.txt). Schemas,
examples and any code are licensed under [Apache-2.0](LICENSE).

## The four positions

1. **Facts and assertions are kept apart.** `fqdn`, `endpoints` and `status`
   are the provider's. `description`, `contact`, `homepage`, `public_key` and
   `metadata` are the operator's, and are labelled as such by being outside
   the `owner` block.
2. **Checks are itemised, dated and expiring.** `owner.verifications` lists
   each check with its type, method, verifier, date and expiry. There is no
   level, score or "verified" badge.
3. **Lifecycle is not liveness.** `status: active` means the identity is in
   good standing, not that the agent is online. An agent that sleeps keeps
   its name.
4. **A person stays accountable.** Identities belong to accounts held by
   people or organisations. An agent may create an identity; it can never
   create an account, and it never holds DNS authority.

## Validate a document

```bash
npx ajv-cli validate -s schema/agent-identity-document.schema.json -d examples/active.json
```

## Render and submit the Internet-Draft

Nothing needs installing. The IETF's [Author Tools](https://author-tools.ietf.org/)
accept kramdown-rfc Markdown and return XML, text and HTML, and run `idnits`.

1. Open <https://author-tools.ietf.org/>, upload
   `draft/draft-alla-agent-identity-document-01.md`, and download the
   generated **XML (v3)** and **text**. Fix anything `idnits` reports.
2. Go to <https://datatracker.ietf.org/submit/>, upload the XML, confirm the
   author details, and click the confirmation link that arrives by e-mail.
   The draft is posted within minutes and announced on `i-d-announce`.
   Individual submissions need no working group and no approval.
3. **Cutoff:** no new drafts are accepted between **2026-11-02 23:59 UTC**
   and the end of the November 2026 meeting (2026-11-14). Submit before the
   cutoff or after the meeting.
4. A draft expires after six months but **stays in the archive for ever**,
   with its posting date. Post `-01` with any changes before expiry.
5. After posting, announce it where the neighbours are: the
   `web-bot-auth@ietf.org` list (for the signed-requests relationship) and the authors
   of the ANS and ADP drafts, by name, with a one-paragraph note of what
   this adds. Do not post to lists where it is not on topic.
6. Request the well-known URI registration for IANA's
   [Well-Known URIs](https://www.iana.org/assignments/well-known-uris/)
   registry as an issue at
   <https://github.com/protocol-registries/well-known-uris>, citing the
   draft. The policy is "Specification
   Required" with expert review; the entry is **provisional** until a
   standards body adopts the format.

To render locally instead: `gem install kramdown-rfc` and
`pip install xml2rfc`, then `kdrfc draft/draft-alla-agent-identity-document-01.md`.

## Status

Version 1 of the format is in production at knownAs.dev. The draft is
`-01`, an individual submission with no standing in the IETF process.
Issues and pull requests are welcome; changes that alter the meaning of a
member need a new `version`.
