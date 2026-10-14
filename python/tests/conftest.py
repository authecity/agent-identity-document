"""Fixtures are recorded responses, shared with every implementation of the
library (``tests/fixtures/*.json`` at the repository root), and the expected
result for each (``tests/expected/*.json``). Nothing here touches a network."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from knownas_verify.fetch import FetchError, RecordedFetcher, Response

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures"
EXPECTED = REPO / "tests" / "expected"


def fixture_names() -> list[str]:
    return sorted(p.stem for p in FIXTURES.glob("*.json"))


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def recorded(fixture: dict[str, Any]) -> RecordedFetcher:
    responses: dict[str, Response | FetchError] = {}
    for url, spec in fixture["responses"].items():
        if "error" in spec:
            responses[url] = FetchError(spec["error"]["kind"], spec["error"]["detail"])
            continue
        body = spec.get("body", "")
        raw = (
            body.encode("utf-8")
            if isinstance(body, str)
            else json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        headers = {k.lower(): v for k, v in spec.get("headers", {}).items()}
        responses[url] = Response(status=int(spec["status"]), headers=headers, body=raw)
    return RecordedFetcher(responses)


def fixture_clock(fixture: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(fixture["now"].replace("Z", "+00:00")).astimezone(UTC)


@pytest.fixture(params=fixture_names())
def case(request: pytest.FixtureRequest) -> tuple[str, dict[str, Any]]:
    name = request.param
    return name, load_fixture(name)
