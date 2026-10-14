"""An API that serves agents only when it knows who answers for them.

    uvicorn app:app

``GET /orders`` needs a signed request whose signer has a verified identity
with a domain check; ``GET /`` is open and says so. The response to a
refusal names the check that failed.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from knownas_fastapi import knownas_identity

from knownas_verify import Verification, summarise

app = FastAPI(title="Orders for named agents")


@app.get("/")
def index() -> dict[str, str]:
    return {
        "hello": "Sign your requests with a key your identity publishes; GET /orders then answers.",
        "how": "https://github.com/authecity/agent-identity-document",
    }


@app.get("/orders")
def orders(identity: Verification = Depends(knownas_identity("owner.domain"))) -> dict[str, object]:
    return {
        "agent": identity.subject,
        "provider": identity.provider,
        "checked": summarise(identity),
        "orders": [{"id": "o-1001", "status": "shipped"}],
    }
