"""Signed requests: the draft's Ed25519 vectors, and the rules around them."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from conftest import REPO
from knownas_verify import Request, require, summarise, verify_request
from knownas_verify.fetch import FetchError, RecordedFetcher, Response
from knownas_verify.sf import parse_dictionary
from knownas_verify.signatures import jwk_thumbprint, signature_base

VECTORS = json.loads(
    (REPO / "tests" / "vectors" / "web-bot-auth-httpsig-00.json").read_text(encoding="utf-8")
)
DIRECTORY_URL = VECTORS["directory"]["url"]
DIRECTORY = Response(
    200,
    {"content-type": VECTORS["directory"]["content_type"], "cache-control": "max-age=300"},
    VECTORS["directory"]["body"].encode("utf-8"),
)
AGENT_DOC = Response(
    200,
    {"content-type": "application/json", "access-control-allow-origin": "*"},
    json.dumps(
        {
            "version": "1",
            "name": "Test agent",
            "status": "active",
            "fqdn": "signature-agent.test",
            "endpoints": {
                "web": "https://signature-agent.test",
                "manifest": "https://signature-agent.test/.well-known/agent-identity.json",
            },
        }
    ).encode(),
)
NOT_FOUND = Response(404, {"content-type": "application/json"}, b'{"error":"not_found"}')


def case(name: str) -> dict:
    for c in VECTORS["cases"]:
        if c["name"] == name:
            return c
    raise KeyError(name)


def request_of(c: dict) -> Request:
    source = case(c["request_from"]) if "request_from" in c else c
    r = source["request"]
    return Request(r["method"], r["url"], tuple((n, v) for n, v in r["headers"]))


def clock(c: dict) -> datetime:
    return datetime.fromisoformat(c["now"].replace("Z", "+00:00"))


def fetcher(**overrides: Response | FetchError) -> RecordedFetcher:
    responses: dict[str, Response | FetchError] = {
        DIRECTORY_URL: DIRECTORY,
        "https://signature-agent.test/.well-known/agent-identity.json": AGENT_DOC,
        "https://signature-agent.test/.well-known/agent-identity-statement.jws": NOT_FOUND,
    }
    responses.update(overrides)
    return RecordedFetcher(responses)


def test_the_test_key_thumbprint_is_the_drafts_kid() -> None:
    key = json.loads(VECTORS["directory"]["body"])["keys"][0]
    assert jwk_thumbprint(key) == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


@pytest.mark.parametrize(
    "c", [c for c in VECTORS["cases"] if "signature_base" in c], ids=lambda c: c["name"]
)
def test_signature_base_matches_the_draft(c: dict) -> None:
    request = request_of(c)
    inputs = parse_dictionary(request.field_value("signature-input") or "")
    assert signature_base(request, inputs["sig2"]) == c["signature_base"]


@pytest.mark.parametrize("c", VECTORS["cases"], ids=lambda c: c["name"])
def test_vectors(c: dict) -> None:
    v = verify_request(request_of(c), fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    expected = c["expected"]
    assert v.check("request.signature").outcome == expected["request.signature"]
    if "detail_contains" in expected:
        assert expected["detail_contains"] in v.check("request.signature").detail
    if "request.agent" in expected:
        assert v.check("request.agent").outcome == expected["request.agent"]
        assert v.subject == "signature-agent.test"
        assert v.status == "active"  # the signer's own record was then read


def test_a_verified_request_reads_the_signers_identity_and_summarises_it() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    v = verify_request(request_of(c), fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    assert require(v, "request.signature", "document.schema", "keys.directory")
    assert "label sig2" in v.check("request.signature").detail
    assert (
        'covers "@authority" "signature-agent";key="agent2"' in v.check("request.signature").detail
    )
    lines = summarise(v)
    assert lines[0] == "signature-agent.test is active, as published by signature-agent.test."
    assert any(line.startswith("The request was signed with a published key") for line in lines)


def test_a_test_key_is_refused_unless_the_caller_is_testing() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    v = verify_request(request_of(c), fetcher=fetcher(), now=clock(c))
    assert v.check("request.signature").outcome == "invalid"
    assert "test key" in v.check("request.signature").detail


def test_a_tampered_signature_is_invalid() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    r = request_of(c)
    headers = tuple(
        (n, v.replace("RdNFx5Bj6au3", "RdNFx5Bj6au4")) if n == "Signature" else (n, v)
        for n, v in r.headers
    )
    v = verify_request(
        Request(r.method, r.url, headers), fetcher=fetcher(), now=clock(c), allow_test_keys=True
    )
    assert v.check("request.signature").outcome == "invalid"
    assert "does not verify" in v.check("request.signature").detail


def test_a_changed_authority_is_invalid() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    r = request_of(c)
    v = verify_request(
        Request(r.method, "https://evil.example/foo", r.headers),
        fetcher=fetcher(),
        now=clock(c),
        allow_test_keys=True,
    )
    assert v.check("request.signature").outcome == "invalid"


def test_discovery_failure_is_unverified_never_invalid() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    for failure in (NOT_FOUND, FetchError("timeout", "no answer within 5s")):
        v = verify_request(
            request_of(c),
            fetcher=fetcher(**{DIRECTORY_URL: failure}),
            now=clock(c),
            allow_test_keys=True,
        )
        assert v.check("request.signature").outcome == "unverified"
        assert "key discovery failed" in v.check("request.signature").detail
        assert v.subject == "signature-agent.test"


def test_an_unknown_keyid_is_unverified_and_a_mislabelled_key_is_invalid() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    other = json.loads(VECTORS["directory"]["body"])
    other["keys"][0]["kid"] = "someone-elses-label"
    mislabelled = Response(200, DIRECTORY.headers, json.dumps(other).encode())
    v = verify_request(
        request_of(c),
        fetcher=fetcher(**{DIRECTORY_URL: mislabelled}),
        now=clock(c),
        allow_test_keys=True,
    )
    assert v.check("request.signature").outcome == "unverified"
    assert "not in the signer's directory" in v.check("request.signature").detail

    other["keys"][0]["kid"] = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
    other["keys"][0]["x"] = (
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"  # another key under the same label
    )
    swapped = Response(200, DIRECTORY.headers, json.dumps(other).encode())
    v2 = verify_request(
        request_of(c),
        fetcher=fetcher(**{DIRECTORY_URL: swapped}),
        now=clock(c),
        allow_test_keys=True,
    )
    assert v2.check("request.signature").outcome == "invalid"
    assert "thumbprint" in v2.check("request.signature").detail


def test_a_signature_must_cover_a_signature_agent_member_and_carry_the_tag() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    r = request_of(c)

    def with_input(value: str) -> Request:
        return Request(
            r.method,
            r.url,
            tuple((n, value) if n == "Signature-Input" else (n, v) for n, v in r.headers),
        )

    uncovered = with_input(
        'sig2=("@authority");created=1735689600;keyid="k";expires=4889289600;tag="web-bot-auth"'
    )
    v = verify_request(uncovered, fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    assert v.check("request.signature").outcome == "invalid"
    assert "does not cover a Signature-Agent member" in v.check("request.signature").detail
    assert v.subject == ""

    other_tag = with_input(
        'sig2=("@authority" "signature-agent";key="agent2");created=1735689600'
        ';keyid="k";expires=4889289600;tag="other"'
    )
    v2 = verify_request(other_tag, fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    assert v2.check("request.signature").outcome == "unverified"
    assert "no signature carries tag" in v2.check("request.signature").detail


def test_a_non_origin_signature_agent_member_is_ignored() -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    r = request_of(c)
    headers = tuple(
        (n, 'agent2="https://signature-agent.test/keys.json"') if n == "Signature-Agent" else (n, v)
        for n, v in r.headers
    )
    v = verify_request(
        Request(r.method, r.url, headers), fetcher=fetcher(), now=clock(c), allow_test_keys=True
    )
    assert v.check("request.signature").outcome == "unverified"
    assert "not an https origin" in v.check("request.signature").detail


def test_an_unsigned_request_is_unverified_and_touches_no_network() -> None:
    f = fetcher()
    v = verify_request(Request("GET", "https://example.com/", ()), fetcher=f, now=datetime.now(UTC))
    assert v.check("request.signature").outcome == "unverified"
    assert f.calls == []


def test_derived_components() -> None:
    r = Request("get", "https://Example.com:443/a/b?x=1&y=two%20words", (("Host", "example.com"),))
    inputs = parse_dictionary(
        'sig=("@method" "@authority" "@scheme" "@path" "@query" "@request-target" "@target-uri" '
        '"@query-param";name="y");created=1;expires=2;keyid="k";tag="web-bot-auth"'
    )
    base = signature_base(r, inputs["sig"])
    assert '"@method": GET' in base
    assert '"@authority": example.com' in base
    assert '"@scheme": https' in base
    assert '"@path": /a/b' in base
    assert '"@query": ?x=1&y=two%20words' in base
    assert '"@request-target": /a/b?x=1&y=two%20words' in base
    assert '"@query-param";name="y": two%20words' in base
