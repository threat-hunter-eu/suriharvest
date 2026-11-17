"""Plain-language summaries, rule highlighting and the web search extras."""

from __future__ import annotations

from suriharvest.summary import rev_diff, summarize
from suriharvest.web import ui

IVANTI = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT Ivanti Successful Response"; flow:established,to_client; '
    'flowbits:isset,ET.CVE-2024-21887; http.stat_code; content:"200"; file.data; content:"uid="; content:"gid="; distance:0; '
    "reference:cve,2024-21887; classtype:attempted-admin; sid:2050297; rev:3; metadata:cve CVE_2024_21887, signature_severity Critical;)"
)


def test_summary_sentence_steps_and_dependency():
    s = summarize(IVANTI, app_layer="http", setters={"ET.CVE-2024-21887": 2050296})
    plain = str(s.plain)
    assert "a host in your network" in plain and "HTTP response" in plain
    assert "<code>200</code>" in plain and "followed by <code>gid=</code>" in plain
    assert "rule 2050296 already set flowbit" in plain
    assert s.steps[0].gate and "set by sid 2050296" in str(s.steps[0].html)
    assert any("somewhere after it" in str(st.html) for st in s.steps)
    assert any("sid 2050296 enabled" in str(n) for n in s.needs)
    assert s.traffic and s.traffic.left.role == "sends the response"
    assert not s.complex and "Needs" in str(s.short)


def test_summary_escapes_and_falls_back():
    evil = 'alert http any any -> any any (msg:"x"; http.uri; content:"<script>"; sid:1; rev:1;)'
    s = summarize(evil, app_layer="http")
    assert "<script>" not in str(s.plain) and "&lt;script&gt;" in str(s.plain)
    lua = 'alert http any any -> any any (msg:"lua rule"; lua:check.lua; sid:2; rev:1;)'
    s = summarize(lua, app_layer="http", msg="lua rule")
    assert s.complex and "the rule's own text is below" in str(s.plain)
    assert summarize("not a rule", msg="m").complex


def test_summary_ioc_and_hex():
    sni = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"bad sni"; tls.sni; content:"evil.example"; endswith; sid:3; rev:1;)'
    s = summarize(sni, app_layer="tls", ioc_type="domain", ioc_value="evil.example")
    assert "server name is <code>evil.example</code>" in str(s.plain)
    hexr = 'alert tcp any any -> any any (msg:"crlf"; content:"|0d 0a|Accept|0d 0a|"; sid:4; rev:1;)'
    assert "\\r\\nAccept" in str(summarize(hexr, app_layer="tcp").plain)


def test_rev_diff():
    old = IVANTI.replace(" distance:0;", "").replace("rev:3", "rev:2")
    assert "Added" in str(rev_diff(old, IVANTI)) and "distance:0" in str(rev_diff(old, IVANTI))
    assert str(rev_diff(None, IVANTI)) == "First seen"
    assert str(rev_diff(IVANTI.replace("rev:3", "rev:2"), IVANTI)) == "No change in the logic"
    # thousands of options stay fast (set membership, not list membership)
    import time

    # (rules of 8 KiB or more never load in Suricata and are refused at ingest: the longest rule has ~450 options)
    many = 'alert tcp any any -> any any (msg:"x"; ' + " ".join(f'content:"c{i}";' for i in range(450)) + " sid:1; rev:1;)"
    assert len(many) < 8192
    t = time.perf_counter()
    assert "added" in str(rev_diff(many.replace('content:"c449";', ""), many)).lower()
    assert time.perf_counter() - t < 2.0


def test_rule_html_highlights_and_escapes():
    html = str(ui.rule_html(IVANTI))
    assert '<span class="k-act">alert</span>' in html and 'class="k-buf">http.stat_code' in html
    assert html.count('class="l"') > 10 and "signature_severity Critical" in html
    assert "<b>" not in str(ui.rule_html('alert http any any -> any any (msg:"<b>"; sid:1;)'))


def test_split_query_and_licences():
    base, extra = ui.split_query('cobalt cve:CVE-2024-3400 loads:7 "two words" metadata:a=b', ["suricata-7", "suricata-8"])
    assert ("cve", "CVE-2024-3400") in extra and ("metadata", "a=b") in extra
    assert "loads:suricata-7" in base and "'two words'" in base
    assert ui.toggle("a app:http", "app:http") == "a" and ui.toggle("a", "app:tls") == "a app:tls"
    assert ui.licence_class("CC-BY-NC-SA-4.0") == "restricted" and ui.licence_class("GPL-3.0-only") == "copyleft"
    assert ui.licence_class("MIT", "no") == "restricted" and ui.licence_short("BSD (sids) and GPL-2.0-only") == "BSD-3 + GPL-2"
    assert ui.short_engine("suricata-8") == "8" and ui.width_class(1, 1000) == "w2" and ui.heat_class(0, 5) == "h0"


def test_summary_verbs_agree_with_plural_buffers():
    rule = (
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"t"; flow:established,to_server; '
        'http.header_names; content:"|0d 0a|Accept"; startswith; http.uri; content:"/x"; sid:1; rev:1;)'
    )
    s = summarize(rule, app_layer="http")
    steps = " ".join(str(st.html) for st in s.steps)
    assert "Header names start with" in steps and "URI contains" in steps
    assert "header names start with" in str(s.plain)
