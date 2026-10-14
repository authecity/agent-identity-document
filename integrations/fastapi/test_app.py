"""The example refuses unsigned and under-verified callers and serves the rest.

Runs without a network: the signer's provider is recorded, and requests are
signed with RFC 9421's test key, which the dependency accepts only because
the test says ``allow_test_keys=True``."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from knownas_fastapi import knownas_identity

from knownas_verify import Verification
from knownas_verify.testing import minimal_document, recorded_provider, sign_request

AGENT = "alice.agents.example"
NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
DOCUMENT_WITH_DOMAIN = minimal_document(
    AGENT,
    owner={
        "verifications": [
            {
                "type": "domain",
                "value": "acme.example",
                "method": "dns-txt",
                "verifier": "agents.example",
                "verified_at": "2026-10-02T09:00:00+00:00",
                "expires_at": "2026-11-01T09:00:00+00:00",
            }
        ],
        "standing": {"account_since": "2026-09-21", "status": "active"},
    },
)


def make_app(document: dict[str, object]) -> TestClient:
    app = FastAPI()
    fetcher = recorded_provider(AGENT, document=document)
    dependency = knownas_identity(
        "owner.domain", fetcher=fetcher, now=lambda: NOW, allow_test_keys=True
    )

    @app.get("/orders")
    def orders(identity: Verification = Depends(dependency)) -> dict[str, str]:
        return {"agent": identity.subject}

    return TestClient(app, base_url="https://api.example")


def signed_headers(path: str = "/orders") -> dict[str, str]:
    request = sign_request(
        "GET", f"https://api.example{path}", agent_origin=f"https://{AGENT}", created=NOW
    )
    return dict(request.headers)


def test_an_unsigned_request_is_refused_with_401() -> None:
    response = make_app(DOCUMENT_WITH_DOMAIN).get("/orders")
    assert response.status_code == 401
    assert response.json()["detail"]["check"] == "request.signature"
    assert response.json()["detail"]["outcome"] == "unverified"
    assert response.headers["www-authenticate"].startswith("Signature")


def test_a_signed_request_from_a_verified_owner_is_served() -> None:
    response = make_app(DOCUMENT_WITH_DOMAIN).get("/orders", headers=signed_headers())
    assert response.status_code == 200, response.text
    assert response.json() == {"agent": AGENT}


def test_a_signed_request_whose_owner_lacks_the_domain_check_gets_403_naming_it() -> None:
    response = make_app(minimal_document(AGENT)).get("/orders", headers=signed_headers())
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["subject"] == AGENT
    assert detail["failed"][0]["check"] == "owner.domain"
    assert detail["failed"][0]["outcome"] == "absent"


def test_a_signature_for_another_path_or_host_is_invalid() -> None:
    client = make_app(DOCUMENT_WITH_DOMAIN)
    # Signed over @authority and @method: the same authority, so the path does
    # not matter for this minimal profile, but another host does.
    other_host = sign_request(
        "GET", "https://evil.example/orders", agent_origin=f"https://{AGENT}", created=NOW
    )
    response = client.get("/orders", headers=dict(other_host.headers))
    assert response.status_code == 401
    assert response.json()["detail"]["outcome"] == "invalid"
