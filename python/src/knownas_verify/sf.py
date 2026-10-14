"""Structured Field Values for HTTP (RFC 8941): the subset HTTP Message
Signatures need, parsed strictly and serialised strictly.

Dictionaries, Items and Inner Lists; bare items of type String, Token,
Integer, Decimal, Byte Sequence and Boolean; parameters on items and inner
lists. A parse error raises :class:`SFError`. Serialisation is the strict
form of section 4, which is what the signature base requires (RFC 9421
section 2.1.2 and 2.5), so a value re-serialised here is byte-identical to
what another conformant implementation produces.

This is a deliberate small implementation rather than a dependency: the
library has one dependency for the lookup half (``jsonschema``) and gains
one for signatures (``cryptography``); the TypeScript twin takes the same
approach. Dates, Display Strings (RFC 9651) are not needed and not parsed.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal


class SFError(ValueError):
    """The field is not a valid Structured Field of the expected type."""


class Token(str):
    """A Token bare item (RFC 8941 section 3.3.4), kept apart from Strings."""

    __slots__ = ()


BareItem = str | Token | int | Decimal | bytes | bool


@dataclass(frozen=True, slots=True)
class Item:
    value: BareItem
    params: dict[str, BareItem] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InnerList:
    items: list[Item]
    params: dict[str, BareItem] = field(default_factory=dict)


Member = Item | InnerList

_TOKEN_START = re.compile(r"[A-Za-z*]")
_TOKEN_CHARS = re.compile(r"[A-Za-z0-9!#$%&'*+\-.^_`|~:/]")
_KEY_START = re.compile(r"[a-z*]")
_KEY_CHARS = re.compile(r"[a-z0-9_\-.*]")
_INTEGER_OR_DECIMAL = re.compile(r"-?(\d+)(\.\d+)?")


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    # -- helpers --------------------------------------------------------
    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def take(self) -> str:
        c = self.peek()
        self.i += 1
        return c

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def done(self) -> bool:
        return self.i >= len(self.s)

    def fail(self, why: str) -> SFError:
        return SFError(f"{why} at offset {self.i} in {self.s!r}")

    # -- RFC 8941 section 4.2 -------------------------------------------
    def dictionary(self) -> dict[str, Member]:
        out: dict[str, Member] = {}
        while not self.done():
            key = self.key()
            if self.peek() == "=":
                self.take()
                out[key] = self.item_or_inner_list()
            else:
                out[key] = Item(True, self.parameters())
            self.skip_ows()
            if self.done():
                return out
            if self.take() != ",":
                raise self.fail("expected ','")
            self.skip_ows()
            if self.done():
                raise self.fail("trailing comma")
        return out

    def item_or_inner_list(self) -> Member:
        if self.peek() == "(":
            return self.inner_list()
        return self.item()

    def inner_list(self) -> InnerList:
        if self.take() != "(":
            raise self.fail("expected '('")
        items: list[Item] = []
        while not self.done():
            self.skip_sp()
            if self.peek() == ")":
                self.take()
                return InnerList(items, self.parameters())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise self.fail("expected space or ')' in inner list")
        raise self.fail("unterminated inner list")

    def item(self) -> Item:
        value = self.bare_item()
        return Item(value, self.parameters())

    def parameters(self) -> dict[str, BareItem]:
        params: dict[str, BareItem] = {}
        while self.peek() == ";":
            self.take()
            self.skip_sp()
            name = self.key()
            if self.peek() == "=":
                self.take()
                params[name] = self.bare_item()
            else:
                params[name] = True
        return params

    def key(self) -> str:
        if not _KEY_START.match(self.peek() or "\0"):
            raise self.fail("expected a key")
        start = self.i
        while not self.done() and _KEY_CHARS.match(self.peek()):
            self.i += 1
        return self.s[start : self.i]

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c == "":
            raise self.fail("expected a bare item")
        if c == "-" or c.isdigit():
            return self.integer_or_decimal()
        if c == '"':
            return self.string()
        if _TOKEN_START.match(c):
            return self.token()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        raise self.fail("unexpected character")

    def integer_or_decimal(self) -> int | Decimal:
        m = _INTEGER_OR_DECIMAL.match(self.s, self.i)
        if not m:
            raise self.fail("expected a number")
        text = m.group(0)
        self.i = m.end()
        if m.group(2) is None:
            if len(m.group(1)) > 15:
                raise self.fail("integer too long")
            return int(text)
        if len(m.group(1)) > 12 or len(m.group(2)) - 1 > 3:
            raise self.fail("decimal too long")
        return Decimal(text)

    def string(self) -> str:
        if self.take() != '"':
            raise self.fail("expected '\"'")
        out = []
        while not self.done():
            c = self.take()
            if c == "\\":
                n = self.take()
                if n not in ('"', "\\"):
                    raise self.fail("bad escape in string")
                out.append(n)
            elif c == '"':
                return "".join(out)
            elif not (0x20 <= ord(c) <= 0x7E):
                raise self.fail("non-ASCII or control character in string")
            else:
                out.append(c)
        raise self.fail("unterminated string")

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while not self.done() and _TOKEN_CHARS.match(self.peek()):
            self.i += 1
        return Token(self.s[start : self.i])

    def byte_sequence(self) -> bytes:
        if self.take() != ":":
            raise self.fail("expected ':'")
        start = self.i
        while not self.done() and self.peek() != ":":
            self.i += 1
        if self.done():
            raise self.fail("unterminated byte sequence")
        raw = self.s[start : self.i]
        self.i += 1
        if not re.fullmatch(r"[A-Za-z0-9+/=]*", raw):
            raise self.fail("bad base64 in byte sequence")
        try:
            return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
        except ValueError as error:
            raise self.fail(f"bad base64: {error}") from error

    def boolean(self) -> bool:
        if self.take() != "?":
            raise self.fail("expected '?'")
        c = self.take()
        if c == "1":
            return True
        if c == "0":
            return False
        raise self.fail("bad boolean")


def parse_dictionary(text: str) -> dict[str, Member]:
    """Parse a Dictionary field value. Several field lines are combined by the
    caller with ``", "`` before parsing, as RFC 8941 section 4.2 requires."""
    p = _Parser(text.strip(" \t"))
    out = p.dictionary()
    if not p.done():
        raise p.fail("trailing characters")
    return out


def parse_item(text: str) -> Item:
    p = _Parser(text.strip(" \t"))
    item = p.item()
    if not p.done():
        raise p.fail("trailing characters")
    return item


# -- RFC 8941 section 4.1, strict serialisation -----------------------------


def serialize_bare_item(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Token):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        q = value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
        text = format(q, "f")
        whole, _, frac = text.partition(".")
        frac = frac.rstrip("0") or "0"
        return f"{whole}.{frac}"
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, str):
        for c in value:
            if not (0x20 <= ord(c) <= 0x7E):
                raise SFError("string contains a non-ASCII or control character")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFError(f"cannot serialise {type(value).__name__}")


def serialize_params(params: dict[str, BareItem]) -> str:
    out = []
    for name, value in params.items():
        if value is True:
            out.append(f";{name}")
        else:
            out.append(f";{name}={serialize_bare_item(value)}")
    return "".join(out)


def serialize_item(item: Item) -> str:
    return serialize_bare_item(item.value) + serialize_params(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    return (
        "("
        + " ".join(serialize_item(i) for i in inner.items)
        + ")"
        + serialize_params(inner.params)
    )


def serialize_member(member: Member) -> str:
    """A Dictionary member's value with its parameters, without the key
    (RFC 9421 section 2.1.2)."""
    if isinstance(member, InnerList):
        return serialize_inner_list(member)
    return serialize_item(member)
