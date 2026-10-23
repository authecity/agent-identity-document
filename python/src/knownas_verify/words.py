"""``summarise``: the checks as short sentences for people.

Each sentence states what was checked and when, in the wording the reference
implementation's ADR 0037 allows ("Owner controls acme.example, checked
2026-10-02, renews 2026-11-01"). None of them says "trusted", "verified owner"
without an object, a number, or a colour. A badge or a listing that prints
anything should print these.
"""

from __future__ import annotations

from .result import UNKNOWN, UNREACHABLE, Check, Verification

#: Words these sentences never use. Tested, because a stray adjective in a
#: summary is how a record becomes an endorsement.
FORBIDDEN_WORDS = ("trusted", "trustworthy", "safe", "verified owner", "level", "score")


def summarise(verification: Verification) -> list[str]:
    lines = [_status_line(verification)]
    for check in verification.outcomes("owner."):
        line = _owner_line(check)
        if line:
            lines.append(line)
    directory = verification.check("keys.directory")
    if directory is not None and directory.outcome == "verified":
        lines.append(
            "No active signing keys."
            if directory.detail == "no active keys"
            else f"{directory.detail[0].upper()}{directory.detail[1:]} published."
        )
    signature = verification.check("request.signature")
    if signature is not None:
        lines.append(_signature_line(signature))
    return lines


def _status_line(v: Verification) -> str:
    if v.status == UNKNOWN:
        return f"No identity is published at {v.subject}."
    if v.status == UNREACHABLE:
        fetched = v.check("document.fetched")
        why = f" ({fetched.detail})" if fetched is not None and fetched.detail else ""
        return f"{v.subject} could not be read{why}."
    if v.status == "suspended":
        return f"{v.subject} is suspended."
    return f"{v.subject} is {v.status}, as published by {v.provider}."


def _owner_line(check: Check) -> str | None:
    kind = check.name.removeprefix("owner.")
    if kind == "standing":
        if check.outcome == "verified" and check.detail:
            return f"{check.detail[0].upper()}{check.detail[1:]}."
        return None
    if check.outcome == "absent":
        return None
    when = f", checked {_day(check.verified_at)}" if check.verified_at else ""
    until = ""
    if check.expires_at:
        until = (
            f", expired {_day(check.expires_at)}"
            if check.outcome == "invalid" and "expired" in check.detail
            else f", renews {_day(check.expires_at)}"
        )
    if kind == "domain":
        subject = check.detail.split(",")[0].strip() if check.detail.startswith("controls") else ""
        if check.outcome == "invalid" and not subject:
            return f"A domain check could not be read ({check.detail})."
        return f"Owner {subject or 'controls a domain'}{when}{until}."
    if kind == "email":
        day = f" {_day(check.verified_at)}" if check.verified_at else ""
        return f"Owner's email address was checked{day}{until}."
    if kind == "github":
        login = check.detail.split(",")[0].strip() if check.detail.startswith("controls") else ""
        if not login:
            return f"A GitHub check could not be read ({check.detail})."
        return f"Owner controls the GitHub account @{login.removeprefix('controls ')}{when}{until}."
    return f"Owner check '{kind}'{when}{until}."


def _signature_line(check: Check) -> str:
    if check.outcome == "verified":
        return f"The request was signed with a published key ({check.detail})."
    if check.outcome == "invalid":
        return f"The request's signature does not verify ({check.detail})."
    return f"The request's signature could not be checked ({check.detail})."


def _day(stamp: str | None) -> str:
    return (stamp or "")[:10]
