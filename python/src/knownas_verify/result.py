"""The result of a verification: a list of checks, each saying what was looked
at and what came of it. There is no trust flag, score or level anywhere in
this module, and no function returns one.

A caller who needs a yes-or-no writes it from the checks it depends on, by
name, with :func:`require` or :func:`assert_verified`, so the policy lives in
the caller's code and names what it rests on.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

#: The four outcomes a check can have. ``verified``, ``invalid`` and
#: ``unverified`` are the Web Bot Auth draft's (Appendix C.1): a fetch that
#: failed is ``unverified``, never ``invalid`` and never ``verified``.
#: ``absent`` is for a thing the record does not carry, so a caller can tell
#: "not checked" from "checked and missing".
Outcome = Literal["verified", "invalid", "unverified", "absent"]

#: Two statuses this library adds to the document's own lifecycle statuses.
#: ``unknown``: the host answered 404 at the document's URI, which the
#: specification defines as "no identity is published here". ``unreachable``:
#: nothing that could be read came back. The two are never merged: the first
#: is a statement by the provider, the second is not.
UNKNOWN = "unknown"
UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class Check:
    """One thing the library looked at.

    ``verified_at`` and ``expires_at`` are copied from the record as
    published (RFC 3339 strings), never reformatted, so a caller can compare
    them with the document itself.
    """

    name: str
    outcome: Outcome
    detail: str = ""
    source: str | None = None
    verified_at: str | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "outcome": self.outcome}
        if self.detail:
            out["detail"] = self.detail
        if self.source is not None:
            out["source"] = self.source
        if self.verified_at is not None:
            out["verified_at"] = self.verified_at
        if self.expires_at is not None:
            out["expires_at"] = self.expires_at
        return out


@dataclass(frozen=True, slots=True)
class Verification:
    """What was checked about one subject, and when.

    ``status`` is the document's own ``status`` member when a document was
    served (``active``, ``suspended``, ``pending`` and so on), or one of
    :data:`UNKNOWN` and :data:`UNREACHABLE`. It is read, never computed.

    ``document`` is the parsed document, for callers who want to read members
    the checks do not cover. It is not part of :meth:`to_dict`.
    """

    subject: str
    provider: str
    status: str
    status_source: str
    observed_at: str
    checks: tuple[Check, ...] = ()
    document: Mapping[str, Any] | None = field(default=None, compare=False, repr=False)

    def __iter__(self) -> Iterator[Check]:
        return iter(self.checks)

    def check(self, name: str) -> Check | None:
        """The check called ``name``, or ``None`` if the library did not run it."""
        for check in self.checks:
            if check.name == name:
                return check
        return None

    def outcomes(self, prefix: str) -> tuple[Check, ...]:
        """Every check whose name starts with ``prefix`` (``"owner."`` for all owner checks)."""
        return tuple(check for check in self.checks if check.name.startswith(prefix))

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "provider": self.provider,
            "status": self.status,
            "status_source": self.status_source,
            "observed_at": self.observed_at,
            "checks": [check.to_dict() for check in self.checks],
        }


class VerificationFailed(Exception):  # noqa: N818  (named for what it reports, as the design record does)
    """Raised by :func:`assert_verified`; names the checks that were not ``verified``."""

    def __init__(self, verification: Verification, failed: tuple[Check | str, ...]) -> None:
        self.verification = verification
        self.failed = failed
        parts = []
        for item in failed:
            if isinstance(item, Check):
                why = f" ({item.detail})" if item.detail else ""
                parts.append(f"{item.name}: {item.outcome}{why}")
            else:
                parts.append(f"{item}: not checked")
        super().__init__(f"{verification.subject}: " + "; ".join(parts))


def require(verification: Verification, *names: str) -> bool:
    """``True`` only if every named check ran and is ``verified``.

    The caller names what it depends on. A check the library did not run
    counts as a failure, so a typo in a name cannot pass.
    """
    if not names:
        raise ValueError("require() needs at least one check name")
    for name in names:
        check = verification.check(name)
        if check is None or check.outcome != "verified":
            return False
    return True


def assert_verified(verification: Verification, *names: str) -> None:
    """Like :func:`require`, but raises :class:`VerificationFailed` naming each failure."""
    if not names:
        raise ValueError("assert_verified() needs at least one check name")
    failed: list[Check | str] = []
    for name in names:
        check = verification.check(name)
        if check is None:
            failed.append(name)
        elif check.outcome != "verified":
            failed.append(check)
    if failed:
        raise VerificationFailed(verification, tuple(failed))
