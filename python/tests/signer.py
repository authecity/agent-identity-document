"""A test-only signer: produce a Web Bot Auth signed request with an Ed25519
key, for interop runs and for tests that need a fresh signature.

It is not part of the package. The platform's SDK will sign requests under
ADR 0039 increment 2; until then this is the reference implementation's own
signer for its vectors, built from the same signature base the verifier
uses, so the two cannot drift apart.
"""

from __future__ import annotations

import base64
import secrets
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from knownas_verify import Request, sf
from knownas_verify.signatures import jwk_thumbprint, signature_base


def sign_request(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    *,
    private_key: Ed25519PrivateKey,
    agent_origin: str,
    label: str = "sig1",
    agent_member: str | None = None,
    created: datetime | None = None,
    lifetime_seconds: int = 300,
    components: tuple[str, ...] = ("@authority", "@method"),
    legacy_agent_form: bool = False,
    include_alg: bool = True,
) -> Request:
    """Return ``Request`` with Signature-Agent, Signature-Input and Signature
    added, signed over ``components`` plus the Signature-Agent member."""
    public = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")
    keyid = jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": x})
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


def directory_for(private_key: Ed25519PrivateKey) -> dict[str, list[dict[str, str]]]:
    public = private_key.public_key().public_bytes_raw()
    x = base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")
    key = {"kty": "OKP", "crv": "Ed25519", "x": x}
    return {"keys": [{**key, "kid": jwk_thumbprint(key), "alg": "ed25519", "use": "sig"}]}
