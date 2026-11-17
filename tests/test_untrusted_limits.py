"""Hostile source content (pre-launch audit): line breaks in exported matcher files, Rich markup in error text,
tar header bombs and deeply nested address lists."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from suriharvest import sync
from suriharvest.export_formats import suricata_update_files
from suriharvest.identity import canon_addr
from suriharvest.parser import ParseError, parse_rule
from suriharvest.web.jobs import Job
from tests.test_pipeline import ws  # noqa: F401 - fixture


def test_msg_line_breaks_cannot_add_suricata_update_matchers(tmp_path: Path):
    hostile = [
        SimpleNamespace(gid=1, sid=9100001 + i, msg=f"Old scanner rule{br}*", canonical_source="x")
        for i, br in enumerate("\r\n\x0b\x0c\x1c\x85 ")
    ]
    suricata_update_files(None, tmp_path, [], set(), {}, excluded=hostile)  # type: ignore[arg-type]
    for name in ("disable.conf", "enable.conf"):
        with open(tmp_path / name, encoding="utf-8") as f:  # universal newlines, as suricata-update reads it
            lines = [ln for ln in f.read().splitlines() if ln.strip() and not ln.startswith("#")]
        assert all(ln.split()[0].count(":") == 1 and ln.split()[0].replace(":", "").isdigit() for ln in lines), lines
    with open(tmp_path / "disable.conf", encoding="utf-8") as f:
        assert len([ln for ln in f.read().splitlines() if not ln.startswith("#")]) == len(hostile)


def test_rich_markup_in_messages_is_escaped(tmp_path: Path):
    from rich.console import Console
    from rich.markup import escape

    out = io.StringIO()
    Console(file=out).print(f"[red]failed[/] evil: {escape('corrupt archive [/x].rules [link=https://evil.example]x')}")
    assert "[/x].rules" in out.getvalue() and "[link=" in out.getvalue()
    job = Job(id="j", kind="update", title="t")
    job.say(f"[red]failed[/] evil: {escape('member [/x].rules')}")
    assert job.lines[-1].endswith("failed evil: member [/x].rules")


def test_markup_in_a_source_failure_does_not_stop_the_other_sources(ws: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest.cli import app

    real = sync.fetch

    def fetch(src, *a, **k):  # type: ignore[no-untyped-def]
        if src.name == "et":
            raise sync.SyncError("corrupt archive 'feed.zip': BadZipFile: Bad CRC-32 for file '[/x].rules'")
        return real(src, *a, **k)

    monkeypatch.setattr(sync, "fetch", fetch)
    r = CliRunner().invoke(app, ["sync"], catch_exceptions=False)
    assert "[/x].rules" in r.output, r.output
    assert "ok" in r.output and "repoB" in r.output.split("[/x].rules", 1)[1], r.output


def test_tar_long_name_header_bomb_is_refused(tmp_path: Path):
    size = 64 * 1024 * 1024  # declared GNU longname size; tarfile would read it whole into memory
    info = tarfile.TarInfo("././@LongLink")
    info.type = tarfile.GNUTYPE_LONGNAME
    info.size = size
    raw = io.BytesIO()
    raw.write(info.tobuf(format=tarfile.GNU_FORMAT))
    raw.write(b"a" * size)
    data = gzip.compress(raw.getvalue(), compresslevel=1)
    with pytest.raises(sync.SyncError, match="long-name header"):
        sync.extract_archive(data, "bomb.tar.gz", tmp_path)


def test_deeply_nested_address_list_is_a_parse_error():
    with pytest.raises(ParseError):
        canon_addr("[" * 1500 + "1.1.1.1" + "]" * 1500)
    assert canon_addr("[[10.0.0.1,10.0.0.2],!1.2.3.4]") == canon_addr("[!1.2.3.4,[10.0.0.2,10.0.0.1]]")
    rule = parse_rule("alert tcp " + "[" * 1500 + "1.1.1.1" + "]" * 1500 + ' any -> any any (msg:"x"; sid:1;)')
    from suriharvest.identity import compute_facts

    with pytest.raises(ParseError):
        compute_facts(rule)
