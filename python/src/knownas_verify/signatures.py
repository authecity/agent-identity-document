"""``verify_request``: an HTTP request signed under Web Bot Auth, checked
against the key its signer publishes, then the signer's identity.

The signature follows HTTP Message Signatures (RFC 9421) as profiled by
``draft-ietf-webbotauth-httpsig-protocol-00`` (the revision the reference
implementation's ADR 0039 pins). What this module makes binding:

- the key is looked up by the **(URL, key) pair**, never by key alone
  (draft section 5.4): the directory fetched is the one named by the
  ``Signature-Agent`` member the signature covers;
- a signature is attributed only to a ``Signature-Agent`` member it
  covers (draft section 5.2.2);
- the three outcomes of Appendix C.1: ``verified``, ``invalid`` and
  ``unverified``; a discovery failure is ``unverified`` and never evicts a
  cached key (section 6.10);
- ``created``, ``expires``, ``keyid`` and ``tag="web-bot-auth"`` are
  required (section 5.2); ``expires`` is enforced by the verifier's clock;
- known test keys are refused unless the caller is testing (section 6.8).

Only Ed25519 keys are read. The directory's ``kid`` must be the JWK
thumbprint of the key it labels (section 5.5), which the library recomputes
rather than trusts.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import sf
from .fetch import TIMEOUT_SECONDS, Fetcher, FetchError, check_subject
from .identity import DIRECTORY_PATH, default_fetcher, read_directory, verify_identity
from .result import UNREACHABLE, Check, Verification

WEB_BOT_AUTH_TAG = "web-bot-auth"

#: Public keys that must never verify a production request (draft section
#: 6.8): RFC 9421's example Ed25519 key (Appendix B.1.4), which the drafts'
#: test vectors also use.
KNOWN_TEST_KEYS_X = frozenset({"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"})

#: How far a ``created`` may sit in the future before it is refused.
MAX_CLOCK_SKEW_SECONDS = 60


@dataclass(frozen=True, slots=True)
class Request:
    """The request as the verifier received it.

    ``url`` is the target URI the request was for, with the scheme and
    authority the verifier served (``https://api.example/path?q=1``).
    ``headers`` may carry a header more than once; values are kept in order.
    """

    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @classmethod
    def from_mapping(
        cls, method: str, url: str, headers: Mapping[str, str | Iterable[str]]
    ) -> Request:
        flat: list[tuple[str, str]] = []
        for name, value in headers.items():
            if isinstance(value, str):
                flat.append((name, value))
            else:
                flat.extend((name, v) for v in value)
        return cls(method=method, url=url, headers=tuple(flat))

    def field_value(self, name: str) -> str | None:
        """RFC 9421 section 2.1: every instance of the field, trimmed, joined
        with a comma and a space; ``None`` if the field is absent."""
        values = [v.strip(" \t") for n, v in self.headers if n.lower() == name.lower()]
        if not values:
            return None
        return ", ".join(values)


class _InvalidError(Exception):
    pass


class _UnverifiedError(Exception):
    pass


def verify_request(
    request: Request,
    *,
    label: str | None = None,
    fetcher: Fetcher | None = None,
    now: datetime | None = None,
    allow_test_keys: bool = False,
    timeout: float = TIMEOUT_SECONDS,
) -> Verification:
    """Verify one Web Bot Auth signature on ``request``, then the signer's identity.

    ``label`` names the signature to check; by default the first whose
    ``tag`` is ``web-bot-auth``. The result is :func:`verify_identity` of
    the signer's host with a ``request.signature`` check added first. When
    the signer cannot be determined at all, the result's subject is empty
    and its only check says why.
    """
    clock = now or datetime.now(UTC)
    fetch = fetcher or default_fetcher()
    timeout = min(timeout, TIMEOUT_SECONDS)

    try:
        chosen, inputs, signature, agent_url, agent_detail = _select(request, label)
    except _InvalidError as error:
        return _lone(request, "invalid", str(error), clock)
    except _UnverifiedError as error:
        return _lone(request, "unverified", str(error), clock)

    try:
        host = check_subject(urlsplit(agent_url).hostname or "")
    except FetchError as error:
        return _lone(request, "unverified", f"Signature-Agent {agent_url!r}: {error.detail}", clock)

    directory_url = f"https://{host}{DIRECTORY_PATH}"
    directory_check, keys = read_directory(fetch, directory_url, timeout)

    try:
        check = _verify_one(
            request, chosen, inputs, signature, keys, directory_check, clock, allow_test_keys
        )
    except _InvalidError as error:
        check = Check("request.signature", "invalid", str(error), source=directory_url)
    except _UnverifiedError as error:
        check = Check("request.signature", "unverified", str(error), source=directory_url)

    identity = verify_identity(host, fetcher=fetch, now=clock, timeout=timeout)
    return Verification(
        subject=identity.subject,
        provider=identity.provider,
        status=identity.status,
        status_source=identity.status_source,
        observed_at=identity.observed_at,
        checks=(
            Check("request.agent", "verified", agent_detail, source=agent_url),
            check,
            *identity.checks,
        ),
        document=identity.document,
    )


def _lone(request: Request, outcome: str, detail: str, clock: datetime) -> Verification:
    return Verification(
        subject="",
        provider="",
        status=UNREACHABLE,
        status_source="none",
        observed_at=clock.isoformat(timespec="seconds").replace("+00:00", "Z"),
        checks=(Check("request.signature", outcome, detail),),  # type: ignore[arg-type]
    )


def _select(request: Request, label: str | None) -> tuple[str, sf.InnerList, bytes, str, str]:
    """Pick the signature to verify and the Signature-Agent member it covers."""
    raw_inputs = request.field_value("signature-input")
    raw_signatures = request.field_value("signature")
    raw_agent = request.field_value("signature-agent")
    if raw_inputs is None or raw_signatures is None:
        raise _UnverifiedError("the request carries no Signature-Input and Signature headers")
    if raw_agent is None:
        raise _UnverifiedError("the request carries no Signature-Agent header")
    try:
        inputs = sf.parse_dictionary(raw_inputs)
        signatures = sf.parse_dictionary(raw_signatures)
    except sf.SFError as error:
        raise _InvalidError(f"malformed signature headers: {error}") from error

    candidates = [label] if label else list(inputs)
    chosen: str | None = None
    for candidate in candidates:
        member = inputs.get(candidate)
        if not isinstance(member, sf.InnerList):
            if label:
                raise _InvalidError(f"no Signature-Input for label {label!r}")
            continue
        if label or member.params.get("tag") == WEB_BOT_AUTH_TAG:
            chosen = candidate
            break
    if chosen is None:
        raise _UnverifiedError(f"no signature carries tag={WEB_BOT_AUTH_TAG!r}")
    inner = inputs[chosen]
    if not isinstance(inner, sf.InnerList):
        raise _InvalidError(f"Signature-Input {chosen!r} is not an Inner List")
    sig_member = signatures.get(chosen)
    if not isinstance(sig_member, sf.Item) or not isinstance(sig_member.value, bytes):
        raise _InvalidError(f"no Signature byte sequence for label {chosen!r}")

    # The Signature-Agent member this signature covers (draft 5.2.1, 5.2.2).
    agent_key: str | None = None
    covers_bare = False
    for item in inner.items:
        if item.value == "signature-agent":
            if "key" in item.params:
                agent_key = str(item.params["key"])
            else:
                covers_bare = True
    agent_value: str | None = None
    kind = ""
    if agent_key is not None:
        try:
            agent_dict = sf.parse_dictionary(raw_agent)
        except sf.SFError as error:
            raise _InvalidError(f"malformed Signature-Agent: {error}") from error
        member = agent_dict.get(agent_key)
        if (
            not isinstance(member, sf.Item)
            or not isinstance(member.value, str)
            or isinstance(member.value, sf.Token)
        ):
            raise _InvalidError(f"Signature-Agent has no String member {agent_key!r}")
        type_param = member.params.get("type", sf.Token("directory"))
        if str(type_param) != "directory":
            raise _UnverifiedError(
                f"Signature-Agent type {type_param!r} is not supported; only directory is"
            )
        agent_value = member.value
        kind = f"member {agent_key!r}"
    elif covers_bare:
        # Legacy sf-string form (draft 5.2.1, Appendix E.1.2/E.2.2).
        try:
            item = sf.parse_item(raw_agent)
        except sf.SFError as error:
            raise _InvalidError(f"malformed legacy Signature-Agent: {error}") from error
        if not isinstance(item.value, str) or isinstance(item.value, sf.Token):
            raise _InvalidError("legacy Signature-Agent is not a String")
        agent_value = item.value
        kind = "legacy string form"
    else:
        raise _InvalidError("the signature does not cover a Signature-Agent member")

    parts = urlsplit(agent_value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise _UnverifiedError(
            f"Signature-Agent {agent_value!r} is not an https origin, so the member is ignored"
        )
    return chosen, inner, sig_member.value, agent_value, f"{kind}, directory type, {agent_value}"


def _verify_one(
    request: Request,
    label: str,
    inner: sf.InnerList,
    signature: bytes,
    keys: list[dict[str, Any]],
    directory_check: Check,
    clock: datetime,
    allow_test_keys: bool,
) -> Check:
    params = inner.params
    for required in ("created", "expires", "keyid"):
        if required not in params:
            raise _InvalidError(f"signature parameters lack {required!r}")
    if params.get("tag") != WEB_BOT_AUTH_TAG:
        raise _InvalidError(f"tag is {params.get('tag')!r}, not {WEB_BOT_AUTH_TAG!r}")
    created, expires, keyid = params["created"], params["expires"], params["keyid"]
    if not isinstance(created, int) or not isinstance(expires, int) or not isinstance(keyid, str):
        raise _InvalidError("created and expires must be Integers and keyid a String")
    now_s = int(clock.timestamp())
    if expires <= now_s:
        raise _InvalidError(f"expired at {_iso(expires)}")
    if created > now_s + MAX_CLOCK_SKEW_SECONDS:
        raise _InvalidError(f"created in the future ({_iso(created)})")
    alg = params.get("alg")
    if alg is not None and str(alg) != "ed25519":
        raise _InvalidError(f"alg {alg!r} is not supported; only ed25519 is")

    names = [str(i.value) for i in inner.items]
    if "@authority" not in names and "@target-uri" not in names:
        raise _InvalidError("the signature covers neither @authority nor @target-uri")

    if directory_check.outcome != "verified":
        raise _UnverifiedError(f"key discovery failed: {directory_check.detail}")
    key = next((k for k in keys if k.get("kid") == keyid), None)
    if key is None:
        raise _UnverifiedError(f"keyid {keyid[:12]}… is not in the signer's directory")
    thumbprint = jwk_thumbprint(key)
    if thumbprint != keyid:
        raise _InvalidError(
            f"the directory labels this key {keyid[:12]}…, but its thumbprint is {thumbprint[:12]}…"
        )
    if key["x"] in KNOWN_TEST_KEYS_X and not allow_test_keys:
        raise _InvalidError("the signing key is a published test key (RFC 9421 Appendix B.1.4)")

    base = signature_base(request, inner)
    try:
        public = Ed25519PublicKey.from_public_bytes(_b64url_decode(str(key["x"])))
    except ValueError as error:
        raise _InvalidError(f"unreadable Ed25519 key: {error}") from error
    try:
        public.verify(signature, base.encode("ascii"))
    except InvalidSignature:
        raise _InvalidError("the signature does not verify over the covered components") from None

    covered = " ".join(sf.serialize_item(i) for i in inner.items)
    remaining = expires - now_s
    when = f"expires in {remaining // 60}m" if remaining < 86400 else f"expires {_iso(expires)}"
    return Check(
        "request.signature",
        "verified",
        f"ed25519, label {label}, kid {keyid[:12]}…, covers {covered}, {when}",
    )


# -- RFC 9421 section 2: the signature base ----------------------------------


def signature_base(request: Request, inner: sf.InnerList) -> str:
    """The signature base for ``inner`` (the label's Signature-Input member)
    over ``request``, per RFC 9421 section 2.5. Raises :class:`_InvalidError` when
    a component cannot be derived."""
    lines: list[str] = []
    seen: set[str] = set()
    for item in inner.items:
        identifier = sf.serialize_item(item)
        if identifier in seen:
            raise _InvalidError(f"component {identifier} is covered twice")
        seen.add(identifier)
        if not isinstance(item.value, str) or isinstance(item.value, sf.Token):
            raise _InvalidError(f"component identifier {identifier} is not a String")
        name = item.value
        value = (
            _derived(request, name, item.params)
            if name.startswith("@")
            else _field(request, name, item.params)
        )
        lines.append(f"{identifier}: {value}")
    lines.append(f'"@signature-params": {sf.serialize_inner_list(inner)}')
    base = "\n".join(lines)
    if not base.isascii():
        raise _InvalidError("the signature base is not ASCII")
    return base


def _derived(request: Request, name: str, params: dict[str, sf.BareItem]) -> str:
    if "req" in params:
        raise _InvalidError(f"{name};req is only valid on a response")
    parts = urlsplit(request.url)
    if name == "@method":
        _no_params(name, params)
        return request.method.upper()
    if name == "@target-uri":
        _no_params(name, params)
        return request.url
    if name == "@authority":
        _no_params(name, params)
        host = (parts.hostname or "").lower()
        if parts.port and not (parts.scheme == "https" and parts.port == 443):
            return f"{host}:{parts.port}"
        return host
    if name == "@scheme":
        _no_params(name, params)
        return parts.scheme.lower()
    if name == "@request-target":
        _no_params(name, params)
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if name == "@path":
        _no_params(name, params)
        return parts.path or "/"
    if name == "@query":
        _no_params(name, params)
        return f"?{parts.query}"
    if name == "@query-param":
        wanted = params.get("name")
        if not isinstance(wanted, str) or set(params) != {"name"}:
            raise _InvalidError("@query-param needs exactly one parameter, name")
        found = [v for k, v in parse_qsl(parts.query, keep_blank_values=True) if k == wanted]
        if len(found) != 1:
            raise _InvalidError(f"@query-param {wanted!r} occurs {len(found)} times")
        return quote(found[0], safe="")
    raise _InvalidError(f"derived component {name!r} is not supported")


def _no_params(name: str, params: dict[str, sf.BareItem]) -> None:
    if params:
        raise _InvalidError(f"{name} takes no parameters")


def _field(request: Request, name: str, params: dict[str, sf.BareItem]) -> str:
    if name != name.lower():
        raise _InvalidError(f"field name {name!r} must be lowercase")
    unknown = set(params) - {"key", "sf", "bs", "tr"}
    if unknown:
        raise _InvalidError(f"field parameter(s) {sorted(unknown)} are not understood")
    if "bs" in params or "tr" in params:
        raise _InvalidError("the bs and tr field parameters are not supported")
    value = request.field_value(name)
    if value is None:
        raise _InvalidError(f"the request has no {name} field")
    if "key" in params:
        key = params["key"]
        if not isinstance(key, str) or isinstance(key, sf.Token):
            raise _InvalidError("the key parameter must be a String")
        try:
            members = sf.parse_dictionary(value)
        except sf.SFError as error:
            raise _InvalidError(f"{name} is not a Dictionary: {error}") from error
        if key not in members:
            raise _InvalidError(f"{name} has no member {key!r}")
        return sf.serialize_member(members[key])
    if "sf" in params:
        try:
            return sf.serialize_member(sf.parse_item(value)) if not value.startswith("(") else value
        except sf.SFError as error:
            raise _InvalidError(f"{name};sf is not a Structured Field: {error}") from error
    return value


# -- keys --------------------------------------------------------------------


def jwk_thumbprint(key: Mapping[str, Any]) -> str:
    """RFC 7638 thumbprint of an OKP key (RFC 8037 Appendix A.3): the
    required members ``crv``, ``kty`` and ``x`` in lexicographic order, no
    whitespace, SHA-256, base64url without padding."""
    required = {"crv": key.get("crv"), "kty": key.get("kty"), "x": key.get("x")}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url_encode(hashlib.sha256(canonical).digest())


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _iso(seconds: int) -> str:
    return (
        datetime.fromtimestamp(seconds, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
