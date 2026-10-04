# The Agent Identity Document: a hosted, accountable public record for AI agents

**Version 1 - 2026-10-03 - Femi Alla, knownAs.dev (Authecity Systems LLC)** - Licensed CC BY 4.0. This is the readable form of `draft-alla-agent-identity-document`; it carries the pending `-01` change noted in CHANGELOG.md.

## Abstract

Autonomous software agents increasingly act on the public internet with no
name that a counterparty can check, no published party that answers for them,
and no way to learn that an operator has withdrawn an agent. This document
specifies the Agent Identity Document, a small JSON document served at a
well-known URI on a hostname assigned to one agent, and the practices an
identity provider follows when it hosts such names for operators who do not
run their own domain.

The document records what the provider knows to be true (the hostname, its
service endpoints and the identity's lifecycle status) separately from what
the operator asserts (a description, a contact, a homepage, a public key), and
publishes the provider's dated, expiring checks on the operator rather than a
single trust level. Lifecycle status is distinct from availability. A
suspended identity publishes a deliberately minimal document. Every identity
is held by an accountable person or organisation; an agent is never itself an
account holder, and agents are never given authority over DNS.

This document describes a practice in production at one provider. It is
published so that the format can be reviewed, implemented by others and mapped
onto related work, and it requests registration of a well-known URI suffix.

# Introduction

Websites solved a version of this problem years ago. A certificate says who a
site is. A published security contact says where to report a problem. A
revoked certificate stops being trusted everywhere at once. Software agents
that call APIs, serve tools and receive webhooks on the open internet have
none of this by default. They borrow their operator's credentials, run from
addresses nobody can trace, and carry no name that another system can look
up.

Several efforts address parts of the gap. The Agent Name Service
[draft-narajala-courtney-ansv2] anchors an agent to a domain the operator
controls and a certificate hierarchy. The A2A Agent Card [A2A] describes an
agent's capabilities at `/.well-known/agent-card.json`. The Agent Discovery
Protocol [draft-pro-adp-agent-discovery] describes discovery metadata.
Web Bot Auth [draft-ietf-webbotauth-httpsig-protocol] lets an agent sign its
requests with a key a verifier can fetch.

Each of these assumes the operator already has something: a domain, a
certificate, a key directory. Most people who build agents have none of
them, and have no wish to run DNS or PKI. This document describes the
missing layer for them: an identity **hosted** by a provider, created in one
request, with the name, TLS, service endpoints and a public record supplied
by the provider, and with a person or organisation accountable for it from
the first minute.

It also records four design positions that distinguish this format from
related work:

1. **Facts and assertions are kept apart.** The provider publishes what it
   made true (name, endpoints, status) and labels what the operator merely
   claims.
2. **Checks on the operator are itemised, dated and expiring.** There is no
   level and no badge; each check says what was checked, how, by whom, when,
   and until when.
3. **Lifecycle is not liveness.** `status` records the operator's and
   provider's decisions about the identity. It never reports whether the
   agent is online.
4. **A person stays accountable.** An identity belongs to an account held by
   a natural person or legal entity. An agent acts under an account; it is
   never one. Agents never hold DNS or registrar authority.

## Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

The terms "identity provider" and "provider" mean the party that assigns
hostnames under a base domain it controls and serves Agent Identity
Documents for them. "Operator" means the account holder responsible for an
agent. "Relying party" means any system that reads an Agent Identity
Document to decide how to treat an agent.

# Model

## Hostnames

The provider controls a base domain. Each identity receives one **identity
hostname**, a single DNS label under the base domain:

~~~
<slug>.<base-domain>              e.g. alice.knownas.dev
~~~

Each service the identity offers receives a **service hostname** with the
service label *leading* the base domain, so that every hostname is exactly one
label below a name the provider can cover with a wildcard certificate:

~~~
<slug>.api.<base-domain>          an HTTP API
<slug>.mcp.<base-domain>          a Model Context Protocol endpoint
<slug>.hooks.<base-domain>        inbound webhooks
~~~

The nested form `api.<slug>.<base-domain>` is NOT used: a wildcard
certificate covers exactly one label, and the nested form would require a
certificate per identity.

A `<slug>` MUST be a valid DNS label [RFC 1035]: lowercase ASCII letters,
digits and hyphens, not beginning or ending with a hyphen. This specification
RECOMMENDS a minimum of 3 and a maximum of 63 characters. The provider MUST
refuse slugs that collide with its own infrastructure names (such as `api`,
`mcp`, `hooks`, `www`) and SHOULD refuse names that impersonate protected
brands, including when a brand appears as a word inside a longer slug
("combosquatting"). Refusal lists are the provider's; this document requires
only that they exist and are enforced before any DNS record is written.

## Accounts and accountability

An identity is created and held by an **account**. An account MUST be held by
a natural person or a legal entity, and the provider MUST verify at minimum
that the account holder controls the e-mail address used to create it. The
provider MAY require a minimum age.

An agent MAY manage identities through a credential scoped to an account, and
MAY be the thing that creates an identity. An agent MUST NOT be able to create
an account. This keeps a person or organisation answerable for every
identity, however it was created.

## Authority over DNS

Agents MUST NOT receive credentials that can modify DNS. The provider's own
provisioning component SHOULD be limited, by the DNS service's access control
rather than by application code alone, to writing address records under the
base domain and nothing else.

# The Agent Identity Document

## Location

The Agent Identity Document is a JSON document [RFC 8259] served over HTTPS
[RFC 9110] at the well-known URI [RFC 8615]

~~~
https://<identity-hostname>/.well-known/agent-identity.json
~~~

Implementations that predate this document serve the same content at
`/.well-known/agent.json`; see Compatibility.

The document MUST be served with `Content-Type: application/json`,
`X-Content-Type-Options: nosniff` and `Access-Control-Allow-Origin: *`, so
that a browser-based relying party can read it. The same headers MUST be sent
on a 404 response for an unallocated or deleted identity, so that a relying
party can distinguish "no such identity" from a network failure.

A relying party MUST treat a 404 at this URI as "no identity is published
here", and MUST NOT treat it as evidence that the hostname was never
allocated: a deleted identity's document is removed before its DNS records
are, and a tombstoned name may still resolve to the provider for a time
(Provider practices).

## Members

The top level is a JSON object. Members fall into two classes, and the class
decides how a relying party may use the value.

### Provider-generated members (facts)

These are projected by the provider from its own records at render time.
They are never writable by the operator; a provider MUST ignore any attempt
to set them.

`version`:
: String. The schema version. This document defines `"1"`. REQUIRED.

`fqdn`:
: String. The identity hostname. REQUIRED.

`status`:
: String. The lifecycle status (Lifecycle status). REQUIRED.

`endpoints`:
: Object mapping an endpoint name to an absolute `https` URL. REQUIRED when
  `status` is not `suspended`. The provider MUST include `web` (the identity
  hostname) and `manifest` (this document's URL). It MUST include one member
  per service the identity offers **and that the provider routes to a live
  origin**, named `api`, `mcp` or `webhooks` (note: the member is
  `webhooks`; its DNS label is `hooks`). A service hostname that is reserved
  but not yet routed MUST NOT be listed, so that a relying party can tell
  "this name is reserved" from "this service answers". Every value MUST
  begin with `https://`.

`owner`:
: Object. The provider's published checks on the account holder and the
  account's standing (The owner block). OPTIONAL; absent when the identity is
  suspended, or when the account is not in good standing.

### Operator-asserted members (claims)

These are supplied by the operator. The provider validates their *form* and
MUST NOT present them as verified unless a check described in The owner block
covers them.

`name`:
: String, at most 120 characters. A display name; defaults to the slug.
  REQUIRED when not suspended.

`description`:
: String, at most 500 characters. OPTIONAL.

`contact`:
: Object with an `email` member, at most 254 characters. OPTIONAL.

`homepage`:
: String, an absolute `https` URL of at most 2048 characters. OPTIONAL.

`public_key`:
: String, at most 4096 characters. An opaque key the operator publishes.
  This document assigns it no verification semantics; see Signed requests.
  OPTIONAL.

`metadata`:
: Object of at most 20 members. Keys MUST match
  `^[a-z0-9][a-z0-9_.-]*$` and be at most 40 characters; values MUST be
  strings of at most 200 characters. OPTIONAL.

All string values in the document MUST be free of C0 control characters
other than those JSON itself requires to be escaped, and the provider MUST
reject input that contains them. All URLs MUST use the `https` scheme; a
provider MUST reject `http`, `javascript`, `data` and every other scheme.
The provider MUST NOT dereference any URL an operator supplies.

## Lifecycle status

`status` takes one of the values below. It records decisions, not
reachability.

| Value | Meaning |
|---|---|
| `pending` | Created; provisioning has not started |
| `provisioning` | DNS records are being written |
| `active` | Provisioned, and in good standing |
| `suspended` | Withdrawn from public view by the operator or the provider; restorable |
| `failed` | Provisioning did not complete |
| `archived` | Retired by the operator; the name is kept |
| `deleting` | Removal in progress; the document disappears shortly |

A relying party MUST NOT infer from `active` that the agent is reachable or
running, and a provider MUST NOT change `status` because an agent's own
endpoints went unreachable. An agent that sleeps at night keeps its name.
Availability, if a relying party needs it, is measured by the relying party.

## The suspended document

When `status` is `suspended`, the provider MUST serve exactly:

~~~
{ "version": "1", "status": "suspended", "fqdn": "alice.knownas.dev" }
~~~

No endpoints, no description, no contact, no owner block. The namespace stays
allocated and DNS stays in place, so the name cannot be taken by someone
else, but nothing the operator wrote continues to be advertised. Suspension
is therefore visible to every relying party within the document's cache
lifetime, which the provider SHOULD keep short (the reference implementation
uses 60 seconds).

Suspension of an **account** MUST stop every credential under it and MUST
suspend every identity it holds.

## The owner block

The `owner` member publishes the provider's checks on the account holder.
There is deliberately no level, score or badge. Each check is its own record:

~~~
"owner": {
  "verifications": [
    { "type": "email", "verified_at": "2026-09-21T14:02:11+00:00" },
    {
      "type": "domain",
      "value": "acme.example",
      "method": "dns-txt",
      "verifier": "knownas.dev",
      "verified_at": "2026-10-02T09:00:00+00:00",
      "expires_at": "2026-11-01T09:00:00+00:00"
    }
  ],
  "standing": { "account_since": "2026-09-21", "status": "active" }
}
~~~

Each member of `verifications` is an object with:

`type`:
: String. This document defines `email` (the account holder controlled the
  sign-up mailbox) and `domain` (the account holder controls a DNS name).
  Further types, such as a check on a legal entity or a natural person, MAY
  be defined; a relying party MUST ignore types it does not understand.

`verified_at`:
: String, an [RFC 3339] timestamp. REQUIRED.

`value`:
: String. What was checked, where that is public (a domain name). For
  `email` the address itself MUST NOT be published. OPTIONAL.

`method`, `verifier`:
: Strings naming how and by whom the check was made. OPTIONAL.

`expires_at`:
: String, an [RFC 3339] timestamp after which the check MUST be treated as
  stale. OPTIONAL; a check without it does not expire.

`standing` carries `account_since` (an [RFC 3339] full-date) and `status`,
which is `active` whenever the block is present; a provider MUST omit the
whole `owner` block rather than publish any other standing.

Relying parties MUST interpret checks by type and date. The absence of a
check is the absence of information and MUST NOT be presented as a
negative finding; many legitimate operators cannot or will not complete
deeper checks. Human-facing presentations SHOULD say what was checked
("owner controls acme.example") and SHOULD NOT say "verified" or "trusted"
without an object.

# Provider practices

A document is only as good as the namespace behind it. A provider that
serves Agent Identity Documents:

1. **Writes explicit DNS records, never a wildcard.** An unallocated name
   MUST return NXDOMAIN. A wildcard would make `paypal.<base-domain>`
   resolve.
2. **Restricts certificate issuance** for the base domain with CAA
   [RFC 8659] to the authority it uses, so that no one else can obtain a
   certificate for a hosted name.
3. **Removes the document before the DNS records** when an identity is
   deleted, and changes only the document on suspension. Everything the
   public can read goes through the document; only reachability goes through
   DNS, and DNS removal may be slow.
4. **Tombstones released names** for a cooling period
   (the reference implementation uses 30 days) during which no new account
   may take the name, while the previous holder may reclaim it at once.
   A leftover record during that period points only at the provider, which
   answers 404.
5. **Keeps an append-only audit trail** of every change to every identity,
   recording whether a person or an agent made it. The application that
   serves the API MUST NOT be able to alter or delete entries.
6. **Enforces quotas** on identities per account and per day, and on
   failure SHOULD suspend rather than bill.

# Relationship to other work

## A2A Agent Cards

An A2A card at `/.well-known/agent-card.json` [A2A] declares that a URL
speaks A2A over a stated binding. A provider MUST NOT generate a card from
the Agent Identity Document alone, because it does not know what the
operator's server speaks. A provider MAY serve a card the operator declares,
beside this document, and when it does the `endpoints` object SHOULD carry
an `agent_card` member pointing to it. A suspended identity MUST serve no
card.

## Signed requests

Where an agent signs its requests with HTTP Message Signatures [RFC 9421] as
profiled by Web Bot Auth [draft-ietf-webbotauth-httpsig-protocol], the natural
`Signature-Agent` value is the identity hostname as an `https` origin, and
the key directory is served by the provider at
`/.well-known/http-message-signatures-directory` on that origin. A verifier
that resolves the signature then already knows where the Agent Identity
Document is. The `public_key` member of this document is unrelated to that
directory and carries no verification semantics of its own.

## Domain-anchored identity

ANS [draft-narajala-courtney-ansv2] and similar work anchor an agent to a
domain the operator controls. This document is complementary: a hosted
identity is for operators who have no domain, and an operator who later
proves control of a domain publishes that as a `domain` check in the owner
block. Nothing here prevents a provider from also issuing ANS records.

## Compatibility

The reference implementation has served this document at
`/.well-known/agent.json` since 2026. That path was also used by A2A before
its version 0.3.0 and has been proposed for other formats. Providers
SHOULD serve this document at `/.well-known/agent-identity.json` and MAY
continue to serve it at `/.well-known/agent.json` during a transition; a
relying party SHOULD try the former first.

# Security Considerations

**Operator-asserted members are claims.** A relying party MUST NOT treat
`contact`, `homepage`, `description`, `public_key` or `metadata` as verified
because they are served over HTTPS from the provider's domain. Only the
checks in `owner` are the provider's statements, and each is bounded by its
dates.

**The provider is a trust anchor.** A hosted identity is only as trustworthy
as the provider's own controls: who may create accounts, how names are
policed, how suspension is applied, and whether the audit trail can be
altered. Provider practices lists the minimum. Relying parties SHOULD
form a view of a provider as they do of a certificate authority.

**Caching bounds suspension.** A relying party that caches the document for
longer than the provider's `Cache-Control` may keep trusting a suspended
identity. Providers SHOULD keep the lifetime short; relying parties making
consequential decisions SHOULD re-fetch at decision time.

**The document is a surface for injection.** It is operator-controlled
content served from a provider hostname. Length caps, control-character
rejection and the `https`-only rule exist so that a document cannot carry a
`javascript:` link or terminal escape into a relying party's logs or UI.
Relying parties MUST still treat every string as untrusted data.

**Identity is not intent.** A deliberately malicious operator can decline to
identify an agent at all. This format changes the default for responsible
operators and makes anonymous agent traffic stand out; it does not stop an
attacker.

# Privacy Considerations

The document publishes: a hostname, endpoints, a status, the operator's
chosen descriptive text, and the provider's checks. For an `email` check the
address is not published, only that a check occurred and when. For a
`domain` check the domain name is published, since control of a public name
is itself public. `account_since` reveals when the account was created and
nothing else about the holder. A provider MUST let an account holder export
and erase their data, and MUST remove an identity's document promptly on
deletion; what the append-only audit trail retains is the provider's
documented retention decision.

# IANA Considerations

IANA is requested to register the following well-known URI suffix in the
"Well-Known URIs" registry [RFC 8615]:

URI suffix:
: agent-identity.json

Change controller:
: Authecity Systems LLC, until a standards body adopts the format

Specification document:
: This document

Status:
: provisional

Related information:
: The JSON Schema and worked examples are maintained at the repository
  referenced in [knownAs.dev].

## Appendix: example documents

An active identity with two services and a verified domain:

~~~
{
 "version": "1",
 "name": "Ada",
 "status": "active",
 "fqdn": "ada.knownas.dev",
 "endpoints": {
  "web": "https://ada.knownas.dev",
  "manifest": "https://ada.knownas.dev/.well-known/agent-identity.json",
  "api": "https://ada.api.knownas.dev",
  "mcp": "https://ada.mcp.knownas.dev"
 },
 "description": "Answers questions about the Acme product catalogue.",
 "owner": {
  "verifications": [
   { "type": "email", "verified_at": "2026-09-21T14:02:11+00:00" },
   { "type": "domain", "value": "acme.example", "method": "dns-txt",
     "verifier": "knownas.dev",
     "verified_at": "2026-10-02T09:00:00+00:00",
     "expires_at": "2026-11-01T09:00:00+00:00" }
  ],
  "standing": { "account_since": "2026-09-21", "status": "active" }
 },
 "contact": { "email": "agents@acme.example" },
 "homepage": "https://acme.example/ada",
 "metadata": { "framework": "langgraph" }
}
~~~

The same identity, suspended:

~~~
{ "version": "1", "status": "suspended", "fqdn": "ada.knownas.dev" }
~~~

The hostnames are the reference implementation's real base domain rather
than the reserved example domains of RFC 2606, because the document
describes a practice in production there.


## References

- [RFC 2119], [RFC 8174]: BCP 14 key words
- [RFC 8259]: JSON
- [RFC 8615]: Well-Known URIs
- [RFC 3339]: timestamps
- [RFC 1035]: DNS labels
- [RFC 8659]: CAA
- [RFC 9110]: HTTP semantics
- [RFC 9421]: HTTP Message Signatures
- [draft-ietf-webbotauth-httpsig-protocol]: Web Bot Auth
- [draft-narajala-courtney-ansv2]: Agent Name Service v2
- [draft-pro-adp-agent-discovery]: Agent Discovery Protocol
- [A2A]: Agent2Agent Protocol Specification, The Linux Foundation, https://a2a-protocol.org/latest/specification/
- [knownAs.dev]: reference implementation, https://knownas.dev/
