"""knownas-verify: read an AI agent's public identity and report what was checked.

The library implements the verifier side of the Agent Identity Document
specification. It reads only public records served by the identity's own
host, reports each thing it looked at as a dated check with one of four
outcomes, and never produces a trust flag, score or level. A relying party
decides for itself, by naming the checks it depends on.

    >>> from knownas_verify import verify_identity, require
    >>> v = verify_identity("alice.knownas.dev")
    >>> v.status
    'active'
    >>> require(v, "document.schema", "owner.domain")
    True
"""

from __future__ import annotations

__version__ = "0.1.0"

from .identity import (
    DIRECTORY_PATH,
    DOCUMENT_PATH,
    SCHEMA_TAG,
    STATEMENT_PATH,
    verify_identity,
)
from .result import (
    UNKNOWN,
    UNREACHABLE,
    Check,
    Outcome,
    Verification,
    VerificationFailed,
    assert_verified,
    require,
)
from .signatures import Request, verify_request
from .words import summarise

__all__ = [
    "DIRECTORY_PATH",
    "DOCUMENT_PATH",
    "SCHEMA_TAG",
    "STATEMENT_PATH",
    "UNKNOWN",
    "UNREACHABLE",
    "Check",
    "Outcome",
    "Request",
    "Verification",
    "VerificationFailed",
    "__version__",
    "assert_verified",
    "require",
    "summarise",
    "verify_identity",
    "verify_request",
]
