"""The fast gid:sid reader of the export uniqueness check must agree with parse_rule whenever it answers."""

from __future__ import annotations

import random

import pytest

from suriharvest.export import SidCollision, _fast_gid_sid, check_unique_sids
from suriharvest.parser import ParseError, parse_rule

H = "alert tcp any any -> any any "
CASES = [
    H + '(msg:"x"; content:"a"; sid:5; rev:1;)',
    H + '(msg:"x"; gid:3; sid:7; rev:1;)',
    H + '(sid:9; msg:"x";)',
    H + '(msg:"x"; SID:11; rev:1;)',  # keywords are case-insensitive
    H + '(msg:"x"; Gid:2; Sid:12; rev:1;)',
    H + '(msg:"sid:99;"; SID:13; rev:1;)',  # a sid-like token inside msg
    H + '(msg:"x"; reference:url,example.org/sid:5; sid:14; rev:1;)',
    H + '(msg:"x"; content:"; sid:98;"; sid:15; rev:1;)',
    H + '(msg:"x"; metadata:foo (sid:97; sid:16; rev:1;)',
    H + '(msg:"x"; content:"gid:4;"; sid:17; rev:1;)',
    H + '(msg:"x"; gid: 5 ; sid : 18 ; rev:1;)',
    H + '(msg:"x"; pcre:"/(sid:96;)/"; sid:19; rev:1;)',
    H + r'(msg:"a\;b"; sid:20; rev:1;)',
    H + '(msg:"x"; gid:"6"; sid:21; rev:1;)',
    H + '(msg:"x"; sidx:1; sid:22; rev:1;)',
]


def _parser(text: str) -> tuple[int, int] | None:
    try:
        r = parse_rule(text)
    except ParseError:
        return None
    return (r.gid, r.sid or 0)


@pytest.mark.parametrize("text", CASES)
def test_fast_path_agrees_with_the_parser(text: str):
    fast = _fast_gid_sid(text)
    assert fast is None or fast == _parser(text), text


def test_fast_path_answers_plain_rules():
    assert _fast_gid_sid(CASES[0]) == (1, 5)
    assert _fast_gid_sid(CASES[3]) == (1, 11)
    assert _fast_gid_sid(CASES[4]) == (2, 12)


def test_fast_path_agrees_on_random_option_soup():
    rnd = random.Random(1234)
    pieces = [
        'msg:"{w}"',
        'content:"{w}"',
        "sid:{n}",
        "SID:{n}",
        "gid:{n}",
        "Gid:{n}",
        "rev:{n}",
        "reference:url,{w}",
        "metadata:{w}",
        'pcre:"/{w}/"',
        "flow:established",
        "classtype:trojan-activity",
    ]
    words = ["a", "sid:3;", "(sid:4", "gid:5;", "x y", "Sid", "(", ";", "sid", '"']
    for _ in range(5000):
        opts = []
        for _ in range(rnd.randint(1, 6)):
            opts.append(rnd.choice(pieces).format(w=rnd.choice(words), n=rnd.randint(1, 9)))
        text = H + "(" + "; ".join(opts) + ";)"
        fast, slow = _fast_gid_sid(text), _parser(text)
        # where the parser refuses a line the check skips it; a fast answer there only makes the check stricter
        if fast is not None and slow is not None:
            assert fast == slow, text


def test_uppercase_duplicate_sid_is_caught(tmp_path):
    f = tmp_path / "r.rules"
    f.write_text(H + '(msg:"a"; sid:5; rev:1;)\n' + H + '(msg:"b"; SID:5; rev:1;)\n' + H + '(msg:"sid:6;"; Sid:6; rev:1;)\n')
    with pytest.raises(SidCollision, match="1:5"):
        check_unique_sids(f)


def test_backslash_before_a_semicolon_always_escapes_it():
    """Suricata does not collapse "\\\\" before looking at ";" (see test_engine.py, checked on 7.0.3, 7.0.17 and
    8.0.8): parser.py, ruleopts.py and the sid map check read these rules alike."""
    from suriharvest import ruleopts
    from suriharvest.parser import ParseError, parse_rule

    bs = "\\"
    pair = f'alert tcp any any -> any any (msg:"x"; metadata:k v{bs}{bs}; sid:19; rev:1;)'
    gid = f'alert tcp any any -> any any (msg:"x"; metadata:k v{bs}{bs}; gid:2; sid:18; rev:1;)'
    with pytest.raises(ParseError):
        parse_rule(pair)
    with pytest.raises(ruleopts.OptionError):
        ruleopts.gid_sid(pair)
    assert (parse_rule(gid).gid, parse_rule(gid).sid) == (1, 18) == ruleopts.gid_sid(gid)
    single = f'alert tcp any any -> any any (msg:"a{bs}; b"; sid:20; rev:1;)'
    assert parse_rule(single).sid == 20 == ruleopts.gid_sid(single)[1]
