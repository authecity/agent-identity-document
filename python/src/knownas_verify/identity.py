"""``verify_identity``: read one identity's public record and report each check.

What is read, and from where (ADR 0049 section 2 of the reference
implementation's design record):

- the Agent Identity Document at ``/.well-known/agent-identity.json`` on the
  subject host, over HTTPS, no redirects;
- the document against the specification's JSON Schema, at the tag this
  package bundles;
- the owner block: each itemised, dated check and the account's standing;
- the Web Bot Auth key directory at
  ``/.well-known/http-message-signatures-directory``;
- the provider's signed statement about the document, once providers serve
  one.

What is never read: a status file or badge that summarises the document
(a rendering, not a source), the A2A agent card, or the agent's endpoints,
which are reported as listed and never probed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib import resources
from typing import Any

import jsonschema

from .fetch import (
    MAX_DIRECTORY_BYTES,
    MAX_DOCUMENT_BYTES,
    TIMEOUT_SECONDS,
    CachingFetcher,
    Fetcher,
    FetchError,
    Response,
    UrllibFetcher,
    check_subject,
)
from .result import UNKNOWN, UNREACHABLE, Check, Verification

DOCUMENT_PATH = "/.well-known/agent-identity.json"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
STATEMENT_PATH = "/.well-known/agent-identity-statement.jws"

#: The specification tag whose schema this package bundles.
SCHEMA_TAG = "v1.0.1-draft"

DOCUMENT_MEDIA_TYPE = "application/json"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"

#: Cache lifetimes the reference implementation serves; a cap, never a floor.
CACHE_CAPS: Mapping[str, int] = {DOCUMENT_PATH: 60, DIRECTORY_PATH: 300}

#: At most this many keys are read from a directory (draft section 6.7).
MAX_DIRECTORY_KEYS = 16

_SCHEMA: dict[str, Any] | None = None


def _schema() -> dict[str, Any]:
    global _SCHEMA
    if _SCHEMA is None:
        text = resources.files(__package__).joinpath("schema/agent-identity-document.schema.json")
        _SCHEMA = json.loads(text.read_text(encoding="utf-8"))
    return _SCHEMA


def default_fetcher() -> Fetcher:
    """The fetcher used when a caller passes none: bounded, no redirects,
    public addresses only, caching within the platform's own lifetimes."""
    return CachingFetcher(UrllibFetcher(), CACHE_CAPS)


def provider_of(hostname: str) -> str:
    """The provider behind a subject: the last two labels of a name with three
    or more (``alice.knownas.dev`` is provided by ``knownas.dev``), else the
    name itself. A heuristic, stated as one: it does not consult the Public
    Suffix List, and a caller who needs that can pass ``providers``."""
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 3 else hostname


def verify_identity(
    subject: str,
    *,
    fetcher: Fetcher | None = None,
    now: datetime | None = None,
    providers: tuple[str, ...] | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> Verification:
    """Read the public record of ``subject`` and report each check.

    ``providers`` restricts subjects to names under the listed suffixes; the
    default accepts any host that serves the document, because the format is
    an open specification. ``now`` is the verifier's clock (UTC), used only to
    decide whether a published check has expired; it is stated in the result.
    """
    clock = now or datetime.now(UTC)
    observed_at = clock.isoformat(timespec="seconds").replace("+00:00", "Z")
    fetch = fetcher or default_fetcher()
    timeout = min(timeout, TIMEOUT_SECONDS)

    try:
        host = check_subject(subject)
    except FetchError as error:
        return Verification(
            subject=subject.strip().lower(),
            provider="",
            status=UNREACHABLE,
            status_source="none",
            observed_at=observed_at,
            checks=(Check("document.fetched", "unverified", error.detail),),
        )

    provider = provider_of(host)
    checks: list[Check] = []

    if providers is not None and not any(
        host == p or host.endswith("." + p) for p in (q.lower() for q in providers)
    ):
        return Verification(
            subject=host,
            provider=provider,
            status=UNREACHABLE,
            status_source="none",
            observed_at=observed_at,
            checks=(
                Check(
                    "document.fetched",
                    "unverified",
                    f"{provider} is not among the providers this verifier accepts",
                ),
            ),
        )

    document_url = f"https://{host}{DOCUMENT_PATH}"
    status = UNREACHABLE
    status_source = "none"
    document: dict[str, Any] | None = None

    try:
        response = fetch.get(
            document_url, accept=DOCUMENT_MEDIA_TYPE, max_bytes=MAX_DOCUMENT_BYTES, timeout=timeout
        )
    except FetchError as error:
        checks.append(Check("document.fetched", "unverified", error.detail, source=document_url))
    else:
        if response.status == 404:
            status = UNKNOWN
            status_source = "document"
            checks.append(
                Check(
                    "document.fetched",
                    "verified",
                    "404: no identity is published at this name" + _header_note(response),
                    source=document_url,
                )
            )
        elif response.status != 200:
            checks.append(
                Check(
                    "document.fetched",
                    "unverified",
                    f"HTTP {response.status}; only 200 and 404 are answers",
                    source=document_url,
                )
            )
        else:
            document, parse_error = _parse_json(response)
            if document is None:
                checks.append(
                    Check(
                        "document.fetched",
                        "invalid",
                        parse_error or "not JSON",
                        source=document_url,
                    )
                )
            else:
                checks.append(
                    Check(
                        "document.fetched",
                        "verified",
                        f"HTTPS, 200, {_content_type(response)}, {_size(response)}",
                        source=document_url,
                    )
                )
                checks.append(_schema_check(document))
                checks.append(_host_check(document, host))
                published = document.get("status")
                if isinstance(published, str) and published:
                    status = published
                    status_source = "document"
                checks.extend(_owner_checks(document, clock))

    directory_url = f"https://{host}{DIRECTORY_PATH}"
    checks.append(_directory_check(fetch, directory_url, timeout))

    statement_url = f"https://{host}{STATEMENT_PATH}"
    checks.append(_statement_check(fetch, statement_url, timeout))

    return Verification(
        subject=host,
        provider=provider,
        status=status,
        status_source=status_source,
        observed_at=observed_at,
        checks=tuple(checks),
        document=document,
    )


def _header_note(response: Response) -> str:
    """The specification asks for three headers on a 404 so a relying party can
    tell "no such identity" from a network failure; say whether they came."""
    wanted = ("x-content-type-options", "access-control-allow-origin")
    missing = [name for name in wanted if response.header(name) is None]
    return "" if not missing else f" (without {', '.join(missing)})"


def _content_type(response: Response) -> str:
    return (response.header("content-type") or "no content-type").split(";")[0].strip()


def _size(response: Response) -> str:
    n = len(response.body)
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} kB"


def _parse_json(response: Response) -> tuple[dict[str, Any] | None, str | None]:
    if not _content_type(response).endswith("json"):
        return None, f"served as {_content_type(response)}, not JSON"
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, f"not JSON: {error}"
    if not isinstance(parsed, dict):
        return None, "not a JSON object"
    return parsed, None


def _schema_check(document: Mapping[str, Any]) -> Check:
    validator = jsonschema.Draft202012Validator(_schema())
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    if not errors:
        return Check(
            "document.schema", "verified", f"agent-identity-document.schema.json {SCHEMA_TAG}"
        )
    # The detail names the schema, not the validator's message: the two
    # implementations must produce the same result, and validators word their
    # messages differently.
    return Check(
        "document.schema",
        "invalid",
        f"does not match agent-identity-document.schema.json {SCHEMA_TAG}",
    )


def _host_check(document: Mapping[str, Any], host: str) -> Check:
    fqdn = document.get("fqdn")
    if fqdn == host:
        return Check("document.host", "verified", f"fqdn is {host}")
    return Check("document.host", "invalid", f"fqdn is {fqdn!r}, fetched from {host}")


def _owner_checks(document: Mapping[str, Any], clock: datetime) -> list[Check]:
    owner = document.get("owner")
    if not isinstance(owner, dict):
        why = (
            "a suspended identity publishes no owner block"
            if document.get("status") == "suspended"
            else "the document carries no owner block"
        )
        return [Check("owner.standing", "absent", why)]

    checks: list[Check] = []
    for entry in owner.get("verifications", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
            checks.append(Check("owner.unknown", "invalid", "a check without a type"))
            continue
        name = f"owner.{entry['type']}"
        verified_at = entry.get("verified_at")
        expires_at = entry.get("expires_at")
        detail_parts: list[str] = []
        if entry.get("value"):
            detail_parts.append(f"controls {entry['value']}")
        if entry.get("method"):
            detail_parts.append(str(entry["method"]))
        if entry.get("verifier"):
            detail_parts.append(f"by {entry['verifier']}")
        detail = ", ".join(detail_parts)
        outcome = "verified"
        if not isinstance(verified_at, str) or _parse_time(verified_at) is None:
            outcome, detail = "invalid", "no readable verified_at"
        elif isinstance(expires_at, str):
            expiry = _parse_time(expires_at)
            if expiry is None:
                outcome, detail = "invalid", "unreadable expires_at"
            elif expiry <= clock:
                outcome = "invalid"
                detail = (detail + "; " if detail else "") + f"expired {expires_at}"
        checks.append(
            Check(
                name,
                outcome,  # type: ignore[arg-type]
                detail,
                verified_at=verified_at if isinstance(verified_at, str) else None,
                expires_at=expires_at if isinstance(expires_at, str) else None,
            )
        )

    standing = owner.get("standing")
    if isinstance(standing, dict) and standing.get("status") == "active":
        checks.append(
            Check(
                "owner.standing",
                "verified",
                f"account since {standing.get('account_since', '?')}, active",
            )
        )
    else:
        checks.append(Check("owner.standing", "invalid", "standing is not active"))
    return checks


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _directory_check(fetch: Fetcher, url: str, timeout: float) -> Check:
    check, _ = read_directory(fetch, url, timeout)
    return check


def read_directory(fetch: Fetcher, url: str, timeout: float) -> tuple[Check, list[dict[str, Any]]]:
    """Fetch and validate a key directory. The keys are returned only when the
    check is ``verified``; otherwise the list is empty and the check says why.
    A 404 or a failed fetch is a discovery failure, ``unverified``: it is not
    evidence about any key a verifier already holds (draft section 6.10)."""
    try:
        response = fetch.get(
            url, accept=DIRECTORY_MEDIA_TYPE, max_bytes=MAX_DIRECTORY_BYTES, timeout=timeout
        )
    except FetchError as error:
        return (
            Check("keys.directory", "unverified", f"discovery failed: {error.detail}", source=url),
            [],
        )
    if response.status != 200:
        return (
            Check(
                "keys.directory",
                "unverified",
                f"discovery failed: HTTP {response.status}",
                source=url,
            ),
            [],
        )
    if _content_type(response) != DIRECTORY_MEDIA_TYPE:
        return (
            Check(
                "keys.directory",
                "invalid",
                f"served as {_content_type(response)}, not {DIRECTORY_MEDIA_TYPE}",
                source=url,
            ),
            [],
        )
    try:
        parsed = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return Check("keys.directory", "invalid", f"not JSON: {error}", source=url), []
    keys = parsed.get("keys") if isinstance(parsed, dict) else None
    if not isinstance(keys, list):
        return Check("keys.directory", "invalid", "no keys array", source=url), []
    if len(keys) > MAX_DIRECTORY_KEYS:
        return (
            Check(
                "keys.directory",
                "invalid",
                f"{len(keys)} keys; at most {MAX_DIRECTORY_KEYS} are read",
                source=url,
            ),
            [],
        )
    for key in keys:
        problem = _key_problem(key)
        if problem:
            return Check("keys.directory", "invalid", problem, source=url), []
    count = len(keys)
    detail = "no active keys" if count == 0 else f"{count} active key{'s' if count != 1 else ''}"
    return Check("keys.directory", "verified", detail, source=url), list(keys)


def _key_problem(key: Any) -> str | None:
    if not isinstance(key, dict):
        return "a key that is not an object"
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return f"unsupported key type {key.get('kty')!r}/{key.get('crv')!r}; only Ed25519 is read"
    if not isinstance(key.get("x"), str) or not isinstance(key.get("kid"), str):
        return "a key without x or kid"
    return None


def _statement_check(fetch: Fetcher, url: str, timeout: float) -> Check:
    try:
        response = fetch.get(
            url, accept="application/jose", max_bytes=MAX_DOCUMENT_BYTES, timeout=timeout
        )
    except FetchError as error:
        return Check("platform.statement", "unverified", f"not fetched: {error.detail}", source=url)
    if response.status == 404:
        return Check(
            "platform.statement",
            "absent",
            "no signed statement is served for this document yet",
            source=url,
        )
    if response.status != 200:
        return Check("platform.statement", "unverified", f"HTTP {response.status}", source=url)
    return Check(
        "platform.statement",
        "unverified",
        "a statement is served, but this version does not verify statements yet",
        source=url,
    )
