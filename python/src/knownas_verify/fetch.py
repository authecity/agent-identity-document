"""Bounded HTTPS fetches of public records, and nothing else.

Every network access the library makes goes through a :class:`Fetcher`. The
default, :class:`UrllibFetcher`, applies the limits the Web Bot Auth draft
asks of verifiers (section 6.7): a byte limit, a wall-clock timeout, no
redirects, and no private, loopback or link-local addresses. It speaks HTTPS
only and never sends anything that identifies the verifier's own users.

Tests pass a :class:`RecordedFetcher` built from fixtures, so the suite runs
without a network.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NoReturn, Protocol

from . import __version__

USER_AGENT = f"knownas-verify/{__version__} (+https://github.com/authecity/agent-identity-document)"

#: A hostname as the Agent Identity Document schema defines it (lowercase
#: labels, at least two). Checked before any network call.
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

#: Limits (ADR 0049 section 3.1). A caller may lower them, never raise them.
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_DIRECTORY_BYTES = 64 * 1024
TIMEOUT_SECONDS = 5.0


class FetchError(Exception):
    """A fetch that produced nothing readable. ``kind`` says why, in one word:
    ``refused`` (the library would not make the request), ``redirect``,
    ``too_large``, ``timeout`` or ``network``."""

    def __init__(self, kind: str, detail: str) -> None:
        self.kind = kind
        self.detail = detail
        super().__init__(f"{kind}: {detail}")


@dataclass(frozen=True, slots=True)
class Response:
    """What came back: the status, the headers with lowercase names, the body."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def max_age(self) -> int | None:
        """``max-age`` from ``Cache-Control``, if present and a whole number."""
        value = self.header("cache-control") or ""
        for directive in value.split(","):
            key, _, number = directive.strip().partition("=")
            if key.strip().lower() == "max-age" and number.strip().isdigit():
                return int(number.strip())
        return None


class Fetcher(Protocol):
    def get(self, url: str, *, accept: str, max_bytes: int, timeout: float) -> Response: ...


def check_subject(hostname: str) -> str:
    """Normalise and validate a subject hostname, or raise :class:`FetchError`
    with kind ``refused``. Refuses IP literals and anything the schema's
    hostname pattern does not accept."""
    name = hostname.strip().rstrip(".").lower()
    if not name or len(name) > 253:
        raise FetchError("refused", "not a hostname")
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        raise FetchError("refused", "IP literals are not identities")
    if not _HOSTNAME.match(name):
        raise FetchError("refused", "not a hostname")
    return name


def refuse_private_addresses(hostname: str) -> None:
    """Resolve ``hostname`` and refuse it if any address is private, loopback,
    link-local, multicast, reserved or unspecified (draft section 6.7).

    This checks the addresses the verifier's resolver returns now; a host
    whose records change between this check and the connection is the
    rebinding case the draft describes, which a library cannot close on its
    own. Deployments that need to can pin the resolver or egress.
    """
    try:
        infos = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise FetchError("network", f"name does not resolve: {error}") from error
    if not infos:
        raise FetchError("network", "name does not resolve")
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        # ``is_global`` is false for every special-purpose range in the IANA
        # registries: private, loopback, link-local, shared address space
        # (100.64/10), documentation, multicast, reserved and unspecified.
        if not address.is_global:
            raise FetchError("refused", f"resolves to a non-public address ({address})")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> NoReturn:
        raise FetchError("redirect", f"{code} to {newurl}; redirects are not followed")


class UrllibFetcher:
    """The default fetcher: HTTPS only, certificate checked, no redirects,
    bounded body, bounded time, public addresses only."""

    def __init__(self, *, context: ssl.SSLContext | None = None) -> None:
        self._context = context or ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            _NoRedirects(), urllib.request.HTTPSHandler(context=self._context)
        )

    def get(self, url: str, *, accept: str, max_bytes: int, timeout: float) -> Response:
        if not url.startswith("https://"):
            raise FetchError("refused", "only https URLs are fetched")
        host = url[len("https://") :].split("/", 1)[0].split(":", 1)[0]
        refuse_private_addresses(check_subject(host))
        request = urllib.request.Request(  # noqa: S310  (https only, checked above)
            url, headers={"Accept": accept, "User-Agent": USER_AGENT}, method="GET"
        )
        started = time.monotonic()
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = _read_bounded(response, max_bytes, timeout - (time.monotonic() - started))
                headers = {k.lower(): v for k, v in response.headers.items()}
                return Response(status=response.status, headers=headers, body=body)
        except urllib.error.HTTPError as error:
            body = _read_bounded(error, max_bytes, timeout - (time.monotonic() - started))
            headers = {k.lower(): v for k, v in error.headers.items()}
            return Response(status=error.code, headers=headers, body=body)
        except FetchError:
            raise
        except TimeoutError as error:
            raise FetchError("timeout", f"no answer within {timeout:.0f}s") from error
        except (urllib.error.URLError, OSError, ssl.SSLError) as error:
            reason = getattr(error, "reason", error)
            if isinstance(reason, FetchError):
                raise reason from error
            if isinstance(reason, TimeoutError | socket.timeout):
                raise FetchError("timeout", f"no answer within {timeout:.0f}s") from error
            raise FetchError("network", str(reason)) from error


def _read_bounded(stream: object, max_bytes: int, remaining: float) -> bytes:
    if remaining <= 0:
        raise FetchError("timeout", "no answer within the time allowed")
    read = getattr(stream, "read")  # noqa: B009
    body: bytes = read(max_bytes + 1)
    if len(body) > max_bytes:
        raise FetchError("too_large", f"body exceeds {max_bytes} bytes")
    return body


@dataclass
class RecordedFetcher:
    """A fetcher that answers from a mapping of URL to response, for tests and
    fixtures. A URL that is not recorded raises a ``network`` error, and a
    recorded ``FetchError`` is raised as given."""

    responses: Mapping[str, Response | FetchError]
    calls: list[str] = field(default_factory=list)

    def get(self, url: str, *, accept: str, max_bytes: int, timeout: float) -> Response:
        self.calls.append(url)
        answer = self.responses.get(url)
        if answer is None:
            raise FetchError("network", f"not recorded: {url}")
        if isinstance(answer, FetchError):
            raise answer
        if len(answer.body) > max_bytes:
            raise FetchError("too_large", f"body exceeds {max_bytes} bytes")
        return answer


@dataclass
class CachingFetcher:
    """Honours ``Cache-Control: max-age`` up to a per-URL-path cap, so a verifier
    that checks many requests does not refetch the same record each time.

    Caps are the platform's own lifetimes (ADR 0049 section 3.2): a caller may
    lower them, never raise them. A failed fetch is never cached: a directory
    that fails to resolve is not evidence (draft section 6.10).
    """

    inner: Fetcher
    caps: Mapping[str, int]
    clock: object = time.monotonic
    _entries: dict[str, tuple[float, Response]] = field(default_factory=dict)

    def get(self, url: str, *, accept: str, max_bytes: int, timeout: float) -> Response:
        now = float(self.clock())  # type: ignore[operator]
        cached = self._entries.get(url)
        if cached is not None and cached[0] > now:
            return cached[1]
        response = self.inner.get(url, accept=accept, max_bytes=max_bytes, timeout=timeout)
        cap = 0
        for path, seconds in self.caps.items():
            if url.endswith(path):
                cap = seconds
        age = response.max_age()
        if response.status == 200 and age is not None and cap > 0:
            self._entries[url] = (now + min(age, cap), response)
        return response
