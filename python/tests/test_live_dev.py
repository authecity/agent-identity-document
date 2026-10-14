"""One live read against the knownAs.dev development environment, opt-in.

Set ``KNOWNAS_VERIFY_LIVE_SUBJECT`` to an identity hostname on dev (for
example ``edge-check.dev.knownas.dev``) to run it. It asserts only what any
published identity guarantees; the owner checks it finds are printed, not
asserted, because they are that identity's own.
"""

from __future__ import annotations

import os

import pytest

from knownas_verify import summarise, verify_identity

SUBJECT = os.environ.get("KNOWNAS_VERIFY_LIVE_SUBJECT")


@pytest.mark.live
@pytest.mark.skipif(not SUBJECT, reason="set KNOWNAS_VERIFY_LIVE_SUBJECT to run the live read")
def test_live_identity_on_dev() -> None:
    assert SUBJECT is not None
    verification = verify_identity(SUBJECT)
    assert verification.check("document.fetched") is not None
    assert verification.status not in ("",)
    for line in summarise(verification):
        print(line)
    if verification.status == "active":
        assert verification.check("document.schema").outcome == "verified"
        assert verification.check("document.host").outcome == "verified"
