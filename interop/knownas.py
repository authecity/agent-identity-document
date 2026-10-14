"""The knownAs side of the interop run: sign a fresh request with the RFC 9421
test key, or verify a request another signer produced, with
``knownas_verify.verify_request`` against a recorded directory for
``signature-agent.test``.

    python knownas.py sign [--legacy] [--no-alg] > out.json
    python knownas.py verify < in.json

Run from this directory with the package's venv (``../python/.venv``) and
``PYTHONPATH=../python/tests`` so the test-only signer is importable.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from knownas_verify import Request, verify_request
from knownas_verify.fetch import RecordedFetcher, Response
from signer import sign_request

HERE = Path(__file__).resolve().parent
VECTORS = json.loads(
    (HERE / ".." / "tests" / "vectors" / "web-bot-auth-httpsig-00.json").read_text()
)
DIRECTORY_URL = VECTORS["directory"]["url"]
TEST_PRIVATE = Ed25519PrivateKey.from_private_bytes(
    base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU==")
)


def fetcher() -> RecordedFetcher:
    doc = {
        "version": "1",
        "name": "Interop test agent",
        "status": "active",
        "fqdn": "signature-agent.test",
        "endpoints": {
            "web": "https://signature-agent.test",
            "manifest": "https://signature-agent.test/.well-known/agent-identity.json",
        },
    }
    return RecordedFetcher(
        {
            DIRECTORY_URL: Response(
                200,
                {"content-type": VECTORS["directory"]["content_type"]},
                VECTORS["directory"]["body"].encode(),
            ),
            "https://signature-agent.test/.well-known/agent-identity.json": Response(
                200, {"content-type": "application/json"}, json.dumps(doc).encode()
            ),
            "https://signature-agent.test/.well-known/agent-identity-statement.jws": Response(
                404, {"content-type": "application/json"}, b"{}"
            ),
        }
    )


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "sign":
        request = sign_request(
            "GET",
            "https://api.example/orders?x=1",
            [],
            private_key=TEST_PRIVATE,
            agent_origin="https://signature-agent.test",
            created=datetime.now(UTC),
            legacy_agent_form="--legacy" in sys.argv,
            include_alg="--no-alg" not in sys.argv,
        )
        print(
            json.dumps(
                {"method": request.method, "url": request.url, "headers": list(request.headers)}
            )
        )
        return 0
    if mode == "verify":
        data = json.load(sys.stdin)
        request = Request(data["method"], data["url"], tuple((n, v) for n, v in data["headers"]))
        v = verify_request(request, fetcher=fetcher(), allow_test_keys=True)
        check = v.check("request.signature")
        agent = v.check("request.agent")
        print(
            json.dumps(
                {
                    "knownas": {
                        "outcome": check.outcome if check else None,
                        "detail": check.detail if check else None,
                        "agent": agent.detail if agent else None,
                        "subject": v.subject,
                        "status": v.status,
                    }
                }
            )
        )
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
