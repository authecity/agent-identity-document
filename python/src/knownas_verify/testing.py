"""Helpers for testing code that verifies agents, without a network.

``sign_request`` signs a request with an Ed25519 key the way an agent does
under Web Bot Auth, built on the library's own signature base so the two
cannot drift. ``recorded_provider`` records the three documents a provider
serves for one identity, so ``verify_identity`` and ``verify_request`` answer
from fixtures. ``TEST_KEY`` is RFC 9421's published Ed25519 test key, which
the library refuses in production and accepts only with
``allow_test_keys=True``.

Nothing here is used by the library itself.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import sf
from .fetch import FetchError, RecordedFetcher, Response
from .identity import DIRECTORY_MEDIA_TYPE, DIRECTORY_PATH, DOCUMENT_PATH, STATEMENT_PATH
from .signatures import Request, jwk_thumbprint, signature_base

#: RFC 9421 Appendix B.1.4, ``test-key-ed25519``. Never in production.
TEST_KEY: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(
    base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU==")
)


def public_jwk(private_key: Ed25519PrivateKey) -> dict[str, str]:
    """The public JWK a directory would list, ``kid`` as the thumbprint."""
    public = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")
    key = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return {**key, "kid": jwk_thumbprint(key), "alg": "ed25519", "use": "sig"}


def directory_for(*private_keys: Ed25519PrivateKey) -> dict[str, list[dict[str, str]]]:
    return {"keys": [public_jwk(k) for k in private_keys]}


def sign_request(
    method: str,
    url: str,
    headers: Iterable[tuple[str, str]] = (),
    *,
    private_key: Ed25519PrivateKey = TEST_KEY,
    agent_origin: str,
    label: str = "sig1",
    agent_member: str | None = None,
    created: datetime | None = None,
    lifetime_seconds: int = 300,
    components: tuple[str, ...] = ("@authority", "@method"),
    legacy_agent_form: bool = False,
    include_alg: bool = True,
) -> Request:
    """``Request`` with Signature-Agent, Signature-Input and Signature added,
    signed over ``components`` plus the Signature-Agent member."""
    keyid = public_jwk(private_key)["kid"]
    member = agent_member or label
    now = created or datetime.now(UTC)
    created_s = int(now.timestamp())

    if legacy_agent_form:
        agent_header = sf.serialize_bare_item(agent_origin)
        agent_component = sf.Item("signature-agent")
    else:
        agent_header = f"{member}={sf.serialize_bare_item(agent_origin)}"
        agent_component = sf.Item("signature-agent", {"key": member})

    items = [sf.Item(c) for c in components] + [agent_component]
    params: dict[str, sf.BareItem] = {"created": created_s}
    if include_alg:
        params["alg"] = "ed25519"
    params["expires"] = created_s + lifetime_seconds
    params["keyid"] = keyid
    params["nonce"] = base64.b64encode(secrets.token_bytes(64)).decode("ascii")
    params["tag"] = "web-bot-auth"
    inner = sf.InnerList(items, params)

    unsigned = Request(method, url, tuple([*headers, ("Signature-Agent", agent_header)]))
    base = signature_base(unsigned, inner)
    signature = private_key.sign(base.encode("ascii"))
    return Request(
        method,
        url,
        tuple(
            [
                *unsigned.headers,
                ("Signature-Input", f"{label}={sf.serialize_inner_list(inner)}"),
                ("Signature", f"{label}={sf.serialize_bare_item(signature)}"),
            ]
        ),
    )


def minimal_document(host: str, **extra: Any) -> dict[str, Any]:
    """An active document with the required members, plus ``extra``."""
    return {
        "version": "1",
        "name": extra.pop("name", host.split(".")[0].capitalize()),
        "status": "active",
        "fqdn": host,
        "endpoints": {
            "web": f"https://{host}",
            "manifest": f"https://{host}{DOCUMENT_PATH}",
        },
        **extra,
    }


def recorded_provider(
    host: str,
    *,
    document: Mapping[str, Any] | None = None,
    keys: Iterable[Ed25519PrivateKey] = (TEST_KEY,),
    document_status: int = 200,
    extra: Mapping[str, Response | FetchError] | None = None,
) -> RecordedFetcher:
    """A fetcher that serves ``host``'s document, key directory and a 404
    statement, as the reference implementation does."""
    doc = dict(document) if document is not None else minimal_document(host)
    responses: dict[str, Response | FetchError] = {
        f"https://{host}{DOCUMENT_PATH}": Response(
            document_status,
            {
                "content-type": "application/json",
                "x-content-type-options": "nosniff",
                "access-control-allow-origin": "*",
                "cache-control": "public, max-age=60",
            },
            json.dumps(doc if document_status == 200 else {"error": "not_found"}).encode(),
        ),
        f"https://{host}{DIRECTORY_PATH}": Response(
            200,
            {"content-type": DIRECTORY_MEDIA_TYPE, "cache-control": "public, max-age=300"},
            json.dumps(directory_for(*keys), separators=(",", ":")).encode(),
        ),
        f"https://{host}{STATEMENT_PATH}": Response(
            404, {"content-type": "application/json"}, b'{"error":"not_found"}'
        ),
    }
    if extra:
        responses.update(extra)
    return RecordedFetcher(responses)
