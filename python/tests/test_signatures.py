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
from knownas_verify.testing import directory_url, sign_request

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


def with_agent(r: Request, value: str) -> Request:
    return Request(
        r.method,
        r.url,
        tuple((n, value) if n == "Signature-Agent" else (n, v) for n, v in r.headers),
    )


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ('agent2="https://signature-agent.test/keys.json"', "names no identity"),
        ('agent2="https://signature-agent.test/?x=1"', "names no identity"),
        ('agent2="http://signature-agent.test"', "not an https URL"),
        ('agent2="https://signature-agent.test:8443"', "a port"),
        ('agent2="https://signature-agent.test";type=directory', "carries parameters"),
        ('agent2="https://signature-agent.test";type=cimd', "carries parameters"),
    ],
)
def test_a_signature_agent_member_that_names_no_identity_is_ignored(value: str, why: str) -> None:
    c = case("E.2.1 Signature-Agent dictionary member present on the request")
    f = fetcher()
    v = verify_request(
        with_agent(request_of(c), value), fetcher=f, now=clock(c), allow_test_keys=True
    )
    assert v.check("request.signature").outcome == "unverified"
    assert why in v.check("request.signature").detail
    assert v.subject == ""
    assert f.calls == []


# -- protocol draft -01: the value is the key directory's URL -----------------

VECTORS_01 = json.loads(
    (REPO / "tests" / "vectors" / "web-bot-auth-httpsig-01.json").read_text(encoding="utf-8")
)
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize("c", VECTORS_01["cases"], ids=lambda c: c["name"])
def test_the_01_vectors(c: dict) -> None:
    request = request_of(c)
    inputs = parse_dictionary(request.field_value("signature-input") or "")
    assert signature_base(request, inputs[c["label"]]) == c["signature_base"]
    v = verify_request(request, fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    assert v.check("request.signature").outcome == c["expected"]["request.signature"]
    assert v.subject == "signature-agent.test"
    assert c["expected"]["agent_detail_contains"] in v.check("request.agent").detail


def test_the_drafts_bare_origin_is_named_as_the_older_form() -> None:
    c = VECTORS_01["cases"][0]
    v = verify_request(request_of(c), fetcher=fetcher(), now=clock(c), allow_test_keys=True)
    assert "-00 form" in v.check("request.agent").detail


def test_a_request_naming_the_key_directory_url_verifies() -> None:
    request = sign_request(
        "GET",
        "https://api.example/orders",
        agent_url=directory_url("signature-agent.test"),
        created=NOW,
    )
    assert f'sig1="{DIRECTORY_URL}"' in (request.field_value("signature-agent") or "")
    f = fetcher()
    v = verify_request(request, fetcher=f, now=NOW, allow_test_keys=True)
    assert require(v, "request.agent", "request.signature", "keys.directory")
    assert v.subject == "signature-agent.test"
    assert v.status == "active"
    assert "key directory URL" in v.check("request.agent").detail
    assert DIRECTORY_URL in f.calls


def test_the_key_directory_url_is_fetched_as_sent_and_names_the_same_identity() -> None:
    sent = f"{DIRECTORY_URL}?v=2"
    request = sign_request("GET", "https://api.example/orders", agent_url=sent, created=NOW)
    f = fetcher(**{sent: DIRECTORY})
    v = verify_request(request, fetcher=f, now=NOW, allow_test_keys=True)
    assert v.check("request.signature").outcome == "verified"
    assert v.subject == "signature-agent.test"
    assert sent in f.calls
    assert DIRECTORY_URL not in f.calls[:1]


def test_sign_request_takes_exactly_one_way_to_name_the_signer() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        sign_request("GET", "https://api.example/")
    with pytest.raises(ValueError, match="exactly one"):
        sign_request(
            "GET",
            "https://api.example/",
            agent_origin="https://signature-agent.test",
            agent_url=DIRECTORY_URL,
        )


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
