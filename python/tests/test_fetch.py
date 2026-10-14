"""The fetcher's limits, without a network."""

from __future__ import annotations

import pytest

from knownas_verify.fetch import (
    USER_AGENT,
    CachingFetcher,
    FetchError,
    RecordedFetcher,
    Response,
    UrllibFetcher,
    check_subject,
    refuse_private_addresses,
)


def test_check_subject_normalises_and_refuses() -> None:
    assert check_subject(" Alice.KnownAs.dev. ") == "alice.knownas.dev"
    for bad in ("", "localhost", "127.0.0.1", "[::1]", "2001:db8::1", "a..b", "-a.b", "a_b.c"):
        with pytest.raises(FetchError) as error:
            check_subject(bad)
        assert error.value.kind == "refused"


def test_private_loopback_and_link_local_addresses_are_refused(monkeypatch) -> None:
    import socket

    def fake(host, port, type=0):
        table = {
            "lo.example": "127.0.0.1",
            "ten.example": "10.1.2.3",
            "link.example": "169.254.1.1",
            "cgnat.example": "100.64.0.1",
            "v6.example": "fd00::1",
            "pub.example": "93.184.216.34",
        }
        return [(socket.AF_INET, type, 6, "", (table[host], port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    for host in ("lo.example", "ten.example", "link.example", "cgnat.example", "v6.example"):
        with pytest.raises(FetchError) as error:
            refuse_private_addresses(host)
        assert error.value.kind == "refused"
    refuse_private_addresses("pub.example")


def test_urllib_fetcher_refuses_http_before_any_network(monkeypatch) -> None:
    import socket

    def boom(*args, **kwargs):
        raise AssertionError("network touched")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(FetchError) as error:
        UrllibFetcher().get("http://alice.knownas.dev/x", accept="*/*", max_bytes=10, timeout=1)
    assert error.value.kind == "refused"


def test_recorded_fetcher_enforces_the_byte_limit() -> None:
    fetcher = RecordedFetcher({"https://a.example/x": Response(200, {}, b"x" * 100)})
    with pytest.raises(FetchError) as error:
        fetcher.get("https://a.example/x", accept="*/*", max_bytes=10, timeout=1)
    assert error.value.kind == "too_large"


def test_caching_honours_max_age_up_to_the_cap_and_never_caches_failures() -> None:
    now = [0.0]
    served = Response(200, {"cache-control": "max-age=86400"}, b"{}")
    inner = RecordedFetcher({"https://a.example/.well-known/agent-identity.json": served})
    cache = CachingFetcher(inner, {"/.well-known/agent-identity.json": 60}, clock=lambda: now[0])
    url = "https://a.example/.well-known/agent-identity.json"
    cache.get(url, accept="*/*", max_bytes=100, timeout=1)
    cache.get(url, accept="*/*", max_bytes=100, timeout=1)
    assert inner.calls == [url]  # the second read came from cache
    now[0] = 61.0
    cache.get(url, accept="*/*", max_bytes=100, timeout=1)
    assert inner.calls == [url, url]  # the cap, not the 86400 s the server offered

    failing = RecordedFetcher({"https://b.example/x": FetchError("network", "down")})
    cache2 = CachingFetcher(failing, {"/x": 60}, clock=lambda: 0.0)
    for _ in range(2):
        with pytest.raises(FetchError):
            cache2.get("https://b.example/x", accept="*/*", max_bytes=100, timeout=1)
    assert failing.calls == ["https://b.example/x"] * 2


def test_the_user_agent_names_the_library_and_nothing_else() -> None:
    assert USER_AGENT.startswith("knownas-verify/")
    assert "github.com/authecity/agent-identity-document" in USER_AGENT
