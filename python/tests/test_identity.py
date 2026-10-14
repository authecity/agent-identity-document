"""The rules each fixture exercises, asserted by name so a failure says which
rule broke rather than which byte differs."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from conftest import REPO, fixture_clock, load_fixture, recorded
from knownas_verify import (
    SCHEMA_TAG,
    UNKNOWN,
    UNREACHABLE,
    VerificationFailed,
    assert_verified,
    require,
    verify_identity,
)
from knownas_verify.identity import provider_of

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def run(name: str):
    fixture = load_fixture(name)
    return verify_identity(
        fixture["subject"], fetcher=recorded(fixture), now=fixture_clock(fixture)
    )


def test_an_active_identity_reads_status_and_each_owner_check() -> None:
    v = run("active")
    assert v.status == "active" and v.status_source == "document"
    assert v.provider == "knownas.dev"
    assert v.check("document.schema").outcome == "verified"
    assert SCHEMA_TAG in v.check("document.schema").detail
    domain = v.check("owner.domain")
    assert domain.outcome == "verified"
    assert domain.verified_at == "2026-10-02T09:00:00+00:00"
    assert domain.expires_at == "2026-11-01T09:00:00+00:00"
    assert "controls acme.example" in domain.detail
    assert v.check("owner.email").outcome == "verified"
    assert v.check("owner.standing").detail == "account since 2026-09-21, active"
    assert v.check("keys.directory").detail == "2 active keys"
    assert v.check("platform.statement").outcome == "absent"
    assert v.document is not None and v.document["name"] == "Alice"


def test_suspended_comes_from_the_document_not_the_empty_key_set() -> None:
    v = run("suspended")
    assert v.status == "suspended"
    assert v.check("owner.standing").outcome == "absent"
    assert v.check("keys.directory").outcome == "verified"
    assert v.check("keys.directory").detail == "no active keys"

    # The same empty key set under an active document is just "no keys".
    v2 = run("no-owner-block")
    assert v2.status == "active"
    assert v2.check("keys.directory").detail == "no active keys"
    assert v2.check("owner.standing").outcome == "absent"


def test_a_404_is_unknown_and_a_failure_is_unreachable_and_they_never_merge() -> None:
    unknown = run("unknown")
    assert unknown.status == UNKNOWN and unknown.status_source == "document"
    assert unknown.check("document.fetched").outcome == "verified"
    assert "no identity is published" in unknown.check("document.fetched").detail

    unreachable = run("unreachable")
    assert unreachable.status == UNREACHABLE and unreachable.status_source == "none"
    assert unreachable.check("document.fetched").outcome == "unverified"
    assert unreachable.check("keys.directory").outcome == "unverified"
    assert "suspended" not in json.dumps(unreachable.to_dict())


def test_an_expired_check_is_invalid_by_the_verifiers_clock() -> None:
    v = run("expired-domain-check")
    domain = v.check("owner.domain")
    assert domain.outcome == "invalid"
    assert "expired 2026-10-01T09:00:00+00:00" in domain.detail
    assert v.check("owner.email").outcome == "verified"
    # Same record, read before the expiry: verified.
    fixture = load_fixture("expired-domain-check")
    earlier = verify_identity(
        fixture["subject"],
        fetcher=recorded(fixture),
        now=datetime(2026, 9, 15, tzinfo=UTC),
    )
    assert earlier.check("owner.domain").outcome == "verified"


def test_wrong_host_and_schema_violations_are_invalid_but_status_is_still_read() -> None:
    v = run("wrong-host-and-schema")
    assert v.check("document.host").outcome == "invalid"
    assert v.check("document.schema").outcome == "invalid"
    assert v.status == "active"
    assert v.check("keys.directory").outcome == "invalid"
    directory = v.check("keys.directory")
    assert "not application/http-message-signatures-directory+json" in directory.detail
    assert v.check("platform.statement").outcome == "unverified"


def test_a_redirect_is_not_followed() -> None:
    v = run("redirected")
    assert v.status == UNREACHABLE
    assert "redirects are not followed" in v.check("document.fetched").detail
    assert v.check("keys.directory").outcome == "verified"


def test_a_bad_subject_never_reaches_the_network() -> None:
    fetcher = recorded(load_fixture("active"))
    for bad in ("127.0.0.1", "[::1]", "not a host", "knownas", "ALICE.knownas.dev."):
        v = verify_identity(bad, fetcher=fetcher, now=NOW)
        if bad == "ALICE.knownas.dev.":
            assert v.subject == "alice.knownas.dev"  # normalised, then fetched
        else:
            assert v.status == UNREACHABLE
            assert v.check("document.fetched").outcome == "unverified"
    assert all("127.0.0.1" not in url and "::1" not in url for url in fetcher.calls)


def test_providers_option_restricts_subjects() -> None:
    fixture = load_fixture("active")
    v = verify_identity(
        fixture["subject"], fetcher=recorded(fixture), now=NOW, providers=("example.org",)
    )
    assert v.status == UNREACHABLE
    assert "not among the providers" in v.check("document.fetched").detail
    ok = verify_identity(
        fixture["subject"], fetcher=recorded(fixture), now=NOW, providers=("KnownAs.dev",)
    )
    assert ok.status == "active"


def test_require_and_assert_name_what_the_caller_depends_on() -> None:
    v = run("active")
    assert require(v, "document.schema", "owner.domain", "keys.directory")
    assert not require(v, "owner.domain", "platform.statement")
    assert not require(v, "owner.domain", "no.such.check")
    try:
        assert_verified(v, "owner.domain", "platform.statement", "no.such.check")
    except VerificationFailed as failed:
        message = str(failed)
        assert "platform.statement: absent" in message
        assert "no.such.check: not checked" in message
    else:
        raise AssertionError("assert_verified did not raise")


def test_provider_heuristic() -> None:
    assert provider_of("alice.knownas.dev") == "knownas.dev"
    assert provider_of("alice.dev.knownas.dev") == "knownas.dev"
    assert provider_of("acme.example") == "acme.example"


def test_the_bundled_schema_is_the_repositorys_schema() -> None:
    package = REPO / "python" / "src" / "knownas_verify" / "schema"
    bundled = (package / "agent-identity-document.schema.json").read_text(encoding="utf-8")
    root = (REPO / "schema" / "agent-identity-document.schema.json").read_text(encoding="utf-8")
    assert json.loads(bundled) == json.loads(root)
