"""Golden identity cases."""

import pytest

from suriharvest.identity import compute_facts, logic_hash, semantic_hash
from suriharvest.parser import ParseError, parse_rule, parse_text

BASE = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"A"; flow:established,to_server; http.uri; content:"/gate.php"; sid:1000001; rev:1;)'


def lh(text: str) -> str:
    return logic_hash(parse_rule(text))


def sh(text: str) -> str:
    return semantic_hash(parse_rule(text))


# --- same logic_hash -------------------------------------------------------------------------------------------


def test_metadata_does_not_change_logic():
    other = (
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Something else"; flow:established,to_server; http.uri; '
        'content:"/gate.php"; classtype:trojan-activity; reference:url,example.com; '
        "metadata:created_at 2020_01_01, signature_severity Major; sid:2999999; rev:7; priority:1;)"
    )
    assert lh(BASE) == lh(other)


def test_hex_and_literal_content_are_the_same():
    a = 'alert tcp any any -> any any (content:"ABC"; sid:1;)'
    b = "alert tcp any any -> any any (content:|41 42 43|; sid:1;)"
    c = 'alert tcp any any -> any any (content:"A|42|C"; sid:1;)'
    assert lh(a) == lh(b) == lh(c)


def test_address_list_order():
    a = 'alert ip [1.1.1.1,2.2.2.2] any -> any any (msg:"x"; sid:1;)'
    b = 'alert ip [2.2.2.2, 1.1.1.1/32] any -> any any (msg:"y"; sid:2;)'
    assert lh(a) == lh(b)


def test_whitespace_and_trailing_semicolon():
    a = 'alert tcp any any -> any any (content:"x"; nocase; sid:1; rev:1;)'
    b = 'alert  tcp any any ->  any any ( content: "x" ;nocase ; sid:1; rev:1 )'
    assert lh(a) == lh(b)


def test_disabled_copy_has_same_hashes():
    on = parse_rule(BASE)
    off = parse_rule("# " + BASE)
    assert not off.enabled and on.enabled
    assert compute_facts(on).content_hash == compute_facts(off).content_hash
    assert logic_hash(on) == logic_hash(off)


def test_action_is_not_logic():
    assert lh(BASE) == lh(BASE.replace("alert ", "drop ", 1))


def test_threshold_and_fast_pattern_are_not_logic():
    a = 'alert tcp any any -> any any (content:"abc"; sid:1;)'
    b = 'alert tcp any any -> any any (content:"abc"; fast_pattern; threshold:type limit,track by_src,count 1,seconds 60; sid:1;)'
    assert lh(a) == lh(b)
    assert compute_facts(parse_rule(a)).alerting_hash != compute_facts(parse_rule(b)).alerting_hash


def test_modifier_order_inside_one_content():
    a = 'alert tcp any any -> any any (content:"abc"; nocase; depth:10; sid:1;)'
    b = 'alert tcp any any -> any any (content:"abc"; depth:10; nocase; sid:1;)'
    assert lh(a) == lh(b)


def test_flow_order():
    a = 'alert tcp any any -> any any (flow:established,to_server; content:"a"; sid:1;)'
    b = 'alert tcp any any -> any any (flow:to_server, established; content:"a"; sid:1;)'
    assert lh(a) == lh(b)


def test_bidirectional_swap():
    a = "alert tcp 1.1.1.1 80 <> 2.2.2.2 any (sid:1;)"
    b = "alert tcp 2.2.2.2 any <> 1.1.1.1 80 (sid:1;)"
    assert lh(a) == lh(b)


# --- different logic_hash --------------------------------------------------------------------------------------


def test_content_order_with_distance_matters():
    a = 'alert tcp any any -> any any (content:"a"; content:"b"; distance:0; sid:1;)'
    b = 'alert tcp any any -> any any (content:"b"; content:"a"; distance:0; sid:1;)'
    assert lh(a) != lh(b)


def test_nocase_matters():
    assert lh('alert tcp any any -> any any (content:"Abc"; sid:1;)') != lh('alert tcp any any -> any any (content:"Abc"; nocase; sid:1;)')


def test_nocase_casefolds():
    assert lh('alert tcp any any -> any any (content:"Abc"; nocase; sid:1;)') == lh(
        'alert tcp any any -> any any (content:"aBC"; nocase; sid:1;)'
    )


def test_sticky_buffer_matters():
    a = 'alert http any any -> any any (http.uri; content:"x"; sid:1;)'
    b = 'alert http any any -> any any (http.host; content:"x"; sid:1;)'
    assert lh(a) != lh(b)


def test_negated_address_matters():
    assert lh("alert ip 1.1.1.1 any -> any any (sid:1;)") != lh("alert ip !1.1.1.1 any -> any any (sid:1;)")


# --- semantic --------------------------------------------------------------------------------------------------


def test_legacy_modifier_equals_sticky_buffer():
    legacy = 'alert http any any -> any any (content:"/gate.php"; http_uri; sid:1;)'
    sticky = 'alert http any any -> any any (http.uri; content:"/gate.php"; sid:1;)'
    assert lh(legacy) != lh(sticky)
    assert sh(legacy) == sh(sticky)


def test_buffer_groups_in_any_order():
    a = 'alert http any any -> any any (http.uri; content:"/a"; http.host; content:"evil.com"; sid:1;)'
    b = 'alert http any any -> any any (http.host; content:"evil.com"; http.uri; content:"/a"; sid:1;)'
    assert lh(a) != lh(b)
    assert sh(a) == sh(b)


def test_startswith_equals_depth():
    a = 'alert http any any -> any any (http.uri; content:"/abc"; startswith; sid:1;)'
    b = 'alert http any any -> any any (http.uri; content:"/abc"; depth:4; sid:1;)'
    assert sh(a) == sh(b)


def test_pcre_delimiters_and_buffer_flags():
    a = 'alert http any any -> any any (pcre:"/a\\/b/Ui"; sid:1;)'
    b = 'alert http any any -> any any (http.uri; pcre:"m#a/b#i"; sid:1;)'
    assert sh(a) == sh(b)


def test_uricontent():
    assert sh('alert http any any -> any any (uricontent:"/x"; sid:1;)') == sh(
        'alert http any any -> any any (http.uri; content:"/x"; sid:1;)'
    )


# --- parser ----------------------------------------------------------------------------------------------------


def test_escaped_semicolon_in_value():
    r = parse_rule(r'alert tcp any any -> any any (msg:"a\;b"; content:"x\;y"; sid:5;)')
    assert r.msg == "a;b"
    assert [o.name for o in r.options] == ["msg", "content", "sid"]


def test_continuation_lines_and_comments():
    text = (
        "# a plain comment\n"
        'alert tcp any any -> any any (msg:"multi"; \\\n'
        '    content:"x"; sid:10; rev:1;)\n'
        "\n"
        '#alert tcp any any -> any any (msg:"off"; content:"y"; sid:11; rev:2;)\n'
        "# alert people about this (not a rule)\n"
        "alert tcp any any -> (broken; sid:12;)\n"
    )
    pf = parse_text(text)
    assert [(r.sid, r.enabled, r.line_no) for r in pf.rules] == [(10, True, 2), (11, False, 5)]
    assert len(pf.errors) == 1 and pf.errors[0][0] == 7


def test_missing_sid_is_an_error():
    with pytest.raises(ParseError):
        parse_rule('alert tcp any any -> any any (msg:"x";)')


# --- facts -----------------------------------------------------------------------------------------------------


def test_ioc_domain():
    f = compute_facts(
        parse_rule('alert dns $HOME_NET any -> any any (msg:"bad"; dns.query; content:"Evil.example"; nocase; endswith; sid:1;)')
    )
    assert (f.ioc_type, f.ioc_value) == ("domain", "evil.example")


def test_ioc_ip_and_not_ioc():
    f = compute_facts(parse_rule('alert ip $HOME_NET any -> 203.0.113.5 any (msg:"c2"; sid:1;)'))
    assert (f.ioc_type, f.ioc_value) == ("ip", "203.0.113.5")
    f = compute_facts(parse_rule(BASE))
    assert f.ioc_type is None


def test_flowbits_and_files():
    f = compute_facts(
        parse_rule(
            "alert http any any -> any any (flowbits:isset,ET.a|ET.b; flowbits:set,ET.c; http.host; dataset:isset,bad,type string,load bad.lst; sid:1;)"
        )
    )
    assert f.flowbits_check == ["flowbits:ET.a", "flowbits:ET.b"]
    assert f.flowbits_set == ["flowbits:ET.c"]
    assert f.files == ["bad.lst"]


def test_foreign_syntax_flag():
    f = compute_facts(parse_rule('alert tcp any any -> any any (msg:"snort3"; service:http; content:"x"; sid:1;)'))
    assert "foreign_syntax" in f.flags


def test_et_metadata():
    f = compute_facts(
        parse_rule(
            'alert tcp any any -> any any (msg:"x"; content:"a"; metadata:attack_profile Client_Endpoint, '
            "mitre_tactic_id TA0011, mitre_technique_id T1071, signature_severity Major; sid:2000001; rev:3;)"
        )
    )
    assert f.metadata["mitre_technique_id"] == ["T1071"]
    assert f.metadata["signature_severity"] == ["Major"]


def test_ioc_url_pair():
    f = compute_facts(
        parse_rule(
            'alert http $HOME_NET any -> any any (msg:"phish"; flow:established,to_server; http.uri; content:"/webchat/"; startswith; '
            'fast_pattern; http.host; content:"woohcp.cc"; endswith; reference:url,openphish.com; sid:6024444; rev:1;)'
        )
    )
    assert (f.ioc_type, f.ioc_value) == ("url", "woohcp.cc/webchat/")


def test_ioc_domain_with_anchoring_pcre():
    f = compute_facts(
        parse_rule('alert tls any any -> any any (tls_sni; content:"upload.ee"; nocase; pcre:"/(^|\\.)upload\\.ee$/"; sid:1;)')
    )
    assert (f.ioc_type, f.ioc_value) == ("domain", "upload.ee")
    f = compute_facts(parse_rule('alert tls any any -> any any (tls_sni; content:"upload.ee"; pcre:"/[a-z]+\\.upload\\.ee$/"; sid:1;)'))
    assert f.ioc_type is None


def test_ioc_dataset_list():
    f = compute_facts(
        parse_rule(
            "alert dns any any -> any any (dns.query; domain; dataset:isset,streaming,type string,load datasets/streaming.txt; sid:1;)"
        )
    )
    assert (f.ioc_type, f.ioc_value) == ("dataset", "streaming")
    assert f.files == ["datasets/streaming.txt"]


def test_retired_flag():
    f = compute_facts(parse_rule('alert http any any -> any any (msg:"ET RETIRED Old thing"; content:"abcd"; sid:2000001; rev:9;)'))
    assert "retired" in f.flags


def test_features_include_detection_globals():
    f = compute_facts(
        parse_rule(
            "alert smb any any -> any any (flow:established; dcerpc.iface:abc; dcerpc.opnum:5; flowbits:set,x; flowbits:isset,y; sid:1;)"
        )
    )
    assert f.features == ["g:dcerpc.iface:abc", "g:dcerpc.opnum:5", "g:flowbits:isset,y"]


def test_features_ignore_short_contents_and_keep_pcre():
    f = compute_facts(parse_rule('alert tcp any any -> any 25 (content:"Subject|3a|"; pcre:"/NOFORN/i"; content:"|00|"; sid:1;)'))
    assert f.features == ["pkt:c:Subject:", "pkt:pcre:/NOFORN/i"]


def test_rule_split_without_backslash_is_repaired():
    text = (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg: "Example split rule [TEST-1]"; flow:established,to_server; '
        'content:"|0a b1|"; offset: 0; depth: 2;\n'
        "classtype:trojan-activity; sid:1000615; rev:20200401;)\n"
        'alert tcp any any -> any any (msg:"next"; content:"x"; sid:2;)\n'
        'alert tcp any any -> any any (msg:"broken, never closed"; content:"y";\n'
        "# a comment stops the repair\n"
    )
    pf = parse_text(text)
    assert [(r.sid, r.repaired) for r in pf.rules] == [(1000615, True), (2, False)]
    assert "repaired_multiline" in compute_facts(pf.rules[0]).flags
    assert len(pf.errors) == 1 and pf.errors[0][2] == "rule without a closing parenthesis"


def test_stray_continuation_backslashes_are_repaired():
    t = 'alert tcp any any -> any [80,443] \\ (msg:"Possible GET a\\;b";\\ gid:1; sid:1000777; rev:1;\\ content:"x\\\\";)'
    pf = parse_text(t)
    assert len(pf.rules) == 1 and pf.rules[0].repaired and pf.rules[0].msg == "Possible GET a;b"
    assert pf.rules[0].get("content") == '"x\\\\"'


def test_every_documented_filter_is_parsed():
    from suriharvest.search import parse_query

    q = parse_query('cat:"ET INFO" enabled:no perf:high redistributable:yes updated<2024-01-01 score>=50 hello')
    assert (
        [k for k, _ in q.filters] == ["cat", "enabled", "perf", "redistributable", "updated<"]
        and q.words == ["hello"]
        and q.min_score == 50
    )


def test_continuation_backslash_with_trailing_spaces():
    text = 'alert tcp any any -> any any (msg: "Example continued rule"; \\ \ncontent:"|01 00|"; offset:1; \\  \nsid:1000516; rev:1;)\n'
    pf = parse_text(text)
    assert [r.sid for r in pf.rules] == [1000516] and not pf.errors


def test_dialect():
    from suriharvest.identity import dialect

    assert dialect(parse_rule('alert http any any -> any any (http.uri; content:"/x"; sid:1;)')) == "suricata"
    assert dialect(parse_rule('alert tcp any any -> any any (dns.query; content:"a.b"; sid:1;)')) == "suricata"
    assert dialect(parse_rule('alert tcp any any -> any any (content:"x"; dataset:isset,a,type string; sid:1;)')) == "suricata"
    assert dialect(parse_rule('alert tcp any any -> any 80 (content:"/x"; http_uri; content:"GET"; http_method; sid:1;)')) == "both"
    assert dialect(parse_rule('alert tcp any any -> any any (content:"x"; sid:1;)')) == "both"
    assert dialect(parse_rule('alert tcp any any -> any any (service:http; content:"x"; sid:1;)')) == "snort"
    assert dialect(parse_rule('alert tcp any any -> any any (http_uri; content:"/x"; sid:1;)')) == "snort"
    f = compute_facts(parse_rule('alert http any any -> any any (http.uri; content:"/x"; sid:1;)'))
    assert "dialect:suricata" in f.flags
