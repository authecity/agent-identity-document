"""A FastAPI dependency that refuses unverified agents.

    from knownas_fastapi import knownas_identity

    @app.get("/orders")
    def orders(identity: Verification = Depends(knownas_identity("owner.domain"))):
        ...

The dependency verifies the request's Web Bot Auth signature against the key
its signer publishes, then reads the signer's identity, and refuses with:

- ``401`` when the signature is not ``verified`` (missing, invalid, or the
  key could not be discovered), naming the outcome and why;
- ``403`` when a check the route names is not ``verified``, naming each one.

The response body says which check failed and what the record said, never
a score. The verified identity is the dependency's return value and is also
on ``request.state.identity``.

Copy this file into your project; it is an example, not a package. It needs
``knownas-verify`` and ``fastapi``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from fastapi import HTTPException
from fastapi import Request as FastAPIRequest

from knownas_verify import Request, Verification, verify_request
from knownas_verify.fetch import Fetcher


def knownas_identity(
    *checks: str,
    fetcher: Fetcher | None = None,
    now: Callable[[], datetime] | None = None,
    allow_test_keys: bool = False,
) -> Callable[[FastAPIRequest], Verification]:
    """Build the dependency. ``checks`` are the check names the route depends
    on beyond the signature itself, for example ``"owner.domain"``.

    ``fetcher``, ``now`` and ``allow_test_keys`` exist for tests; leave them
    at their defaults in production."""

    def dependency(request: FastAPIRequest) -> Verification:
        signed = Request(
            request.method,
            str(request.url),
            tuple(
                (name.decode("latin-1"), value.decode("latin-1"))
                for name, value in request.headers.raw
            ),
        )
        verification = verify_request(
            signed,
            fetcher=fetcher,
            now=now() if now else None,
            allow_test_keys=allow_test_keys,
        )
        signature = verification.check("request.signature")
        if signature is None or signature.outcome != "verified":
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "request_not_verified",
                    "check": "request.signature",
                    "outcome": signature.outcome if signature else "absent",
                    "why": signature.detail if signature else "",
                },
                headers={"WWW-Authenticate": 'Signature realm="knownas"'},
            )
        failed = []
        for name in checks:
            found = verification.check(name)
            if found is None or found.outcome != "verified":
                failed.append(
                    {
                        "check": name,
                        "outcome": found.outcome if found else "absent",
                        "why": found.detail if found else "the record does not carry it",
                    }
                )
        if failed:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "identity_check_failed",
                    "subject": verification.subject,
                    "failed": failed,
                },
            )
        request.state.identity = verification
        return verification

    return dependency
