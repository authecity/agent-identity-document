"""The Structured Fields subset: RFC 8941's own examples, parsed and re-serialised."""

from __future__ import annotations

from decimal import Decimal

import pytest

from knownas_verify import sf


def test_dictionary_with_items_inner_lists_and_parameters() -> None:
    d = sf.parse_dictionary("a=1, b=2;x=1;y=2, c=(a   b    c), d")
    assert d["a"] == sf.Item(1)
    assert d["b"] == sf.Item(2, {"x": 1, "y": 2})
    assert isinstance(d["c"], sf.InnerList)
    assert [i.value for i in d["c"].items] == [sf.Token("a"), sf.Token("b"), sf.Token("c")]
    assert d["d"] == sf.Item(True)
    # RFC 9421 section 2.1.2's canonical member values.
    assert sf.serialize_member(d["a"]) == "1"
    assert sf.serialize_member(d["d"]) == "?1"
    assert sf.serialize_member(d["b"]) == "2;x=1;y=2"
    assert sf.serialize_member(d["c"]) == "(a b c)"


def test_signature_input_round_trips_byte_for_byte() -> None:
    text = (
        'sig2=("@authority" "signature-agent";key="agent2");created=1735689600'
        ';keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"'
        ';expires=4889289600;nonce="n9p4/33+xm==";tag="web-bot-auth"'
    )
    d = sf.parse_dictionary(text)
    inner = d["sig2"]
    assert isinstance(inner, sf.InnerList)
    assert sf.serialize_inner_list(inner) == text[len("sig2=") :]
    assert inner.params["created"] == 1735689600
    assert inner.items[1].params["key"] == "agent2"


def test_bare_item_types() -> None:
    assert sf.parse_item('"a \\"quoted\\" \\\\ string"').value == 'a "quoted" \\ string'
    assert sf.parse_item(":AQID:").value == b"\x01\x02\x03"
    assert sf.parse_item("?0").value is False
    assert sf.parse_item("4.50").value == Decimal("4.50")
    assert sf.serialize_bare_item(Decimal("4.50")) == "4.5"
    assert sf.serialize_bare_item(Decimal("1")) == "1.0"
    assert sf.serialize_bare_item(b"\x01\x02\x03") == ":AQID:"
    assert sf.serialize_bare_item(sf.Token("web-bot-auth")) == "web-bot-auth"
    assert sf.serialize_bare_item("web-bot-auth") == '"web-bot-auth"'


@pytest.mark.parametrize(
    "bad",
    [
        "a=",
        "a=1,",
        '"unterminated',
        "a=(1 2",
        "a=1;;b",
        "A=1",
        ":not base64!:",
        "?2",
        '"non\tascii"',
        "a=1 b=2",
    ],
)
def test_malformed_input_raises(bad: str) -> None:
    with pytest.raises(sf.SFError):
        sf.parse_dictionary(bad)


def test_a_string_with_non_ascii_cannot_be_serialised() -> None:
    with pytest.raises(sf.SFError):
        sf.serialize_bare_item("café")
