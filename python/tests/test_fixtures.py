"""Every recorded fixture produces exactly the expected result.

The expected files are the contract both implementations must meet. To
regenerate them after a deliberate change, run with ``UPDATE_EXPECTED=1`` and
review the diff; never regenerate to make a failing test pass.
"""

from __future__ import annotations

import json
import os

from conftest import EXPECTED, fixture_clock, recorded
from knownas_verify import summarise, verify_identity
from knownas_verify.words import FORBIDDEN_WORDS


def test_fixture_matches_expected(case) -> None:
    name, fixture = case
    fetcher = recorded(fixture)
    verification = verify_identity(fixture["subject"], fetcher=fetcher, now=fixture_clock(fixture))
    actual = {"verification": verification.to_dict(), "summary": summarise(verification)}
    path = EXPECTED / f"{name}.json"
    if os.environ.get("UPDATE_EXPECTED") == "1" or not path.exists():
        path.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
    expected = json.loads(path.read_text(encoding="utf-8"))
    assert actual == expected, f"{name}: result differs from tests/expected/{name}.json"


def test_fixture_fetches_only_the_three_records(case) -> None:
    _, fixture = case
    fetcher = recorded(fixture)
    verify_identity(fixture["subject"], fetcher=fetcher, now=fixture_clock(fixture))
    host = fixture["subject"]
    assert set(fetcher.calls) <= {
        f"https://{host}/.well-known/agent-identity.json",
        f"https://{host}/.well-known/http-message-signatures-directory",
        f"https://{host}/.well-known/agent-identity-statement.jws",
    }


def test_no_summary_uses_a_forbidden_word(case) -> None:
    _, fixture = case
    verification = verify_identity(
        fixture["subject"], fetcher=recorded(fixture), now=fixture_clock(fixture)
    )
    text = " ".join(summarise(verification)).lower()
    for word in FORBIDDEN_WORDS:
        assert word not in text, f"{word!r} in {text!r}"
    for check in verification.checks:
        assert check.outcome in ("verified", "invalid", "unverified", "absent")


def test_no_result_carries_a_trust_field(case) -> None:
    _, fixture = case
    verification = verify_identity(
        fixture["subject"], fetcher=recorded(fixture), now=fixture_clock(fixture)
    )
    flat = json.dumps(verification.to_dict()).lower()
    for field in ('"trusted"', '"score"', '"level"', '"ok"'):
        assert field not in flat
