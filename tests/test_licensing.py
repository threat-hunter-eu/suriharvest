"""Copyright lines, licence headers on loose rule files, git licence files."""

from __future__ import annotations

from suriharvest.release import copyright_lines
from tests.test_pipeline import run
from tests.test_release import released, ws  # noqa: F401 - fixtures

BSD_BLOCK = [
    "Copyright (c) 2003-2026, Emerging Threats",
    "All rights reserved.",
    "* Redistributions of source code must retain the above copyright notice, this list of conditions and the following",
    "* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the",
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS' AND ANY EXPRESS OR IMPLIED WARRANTIES,",
    "COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR",
]


def test_copyright_lines_are_holders_not_licence_conditions():
    assert copyright_lines([BSD_BLOCK]) == ["Copyright (c) 2003-2026, Emerging Threats"]
    mit = ["MIT License", "", "Copyright (c) 2017 Open Information Security Foundation", "", "The above copyright notice and this"]
    assert copyright_lines([mit]) == ["Copyright (c) 2017 Open Information Security Foundation"]
    assert copyright_lines([["Copyright(C) 2015-2022, Stamus Networks"], ["(c) 2024 Someone"], ["© 2020 X"]]) == [
        "Copyright(C) 2015-2022, Stamus Networks",
        "(c) 2024 Someone",
        "© 2020 X",
    ]
    # the SPDX template line is not a holder; duplicates are listed once
    assert copyright_lines([["Copyright (c) <year> <copyright holders>"], ["Copyright 2022 by Volexity, Inc."] * 2]) == [
        "Copyright 2022 by Volexity, Inc."
    ]


def test_every_redistributable_catalog_source_names_its_copyright_holder():
    """The bundled catalog carries a copyright / attribution line for every source the release may publish
    (read from the publisher's LICENSE or feed header; publishers that state none are named and say so)."""
    from suriharvest.config import catalog_sources

    missing = [c.name for c in catalog_sources() if c.redistribute == "yes" and not c.copyright]
    assert missing == []
    by = {c.name: c.copyright for c in catalog_sources()}
    assert by["ptrules-open"] == "Copyright (c) 2024-2026 JSC Positive Technologies"
    assert by["aleksibovellan-nmap"] == "Copyright (c) 2023 Aleksi Bovellan"
    assert "Etnetera" in by["etnetera-aggressive"] and "Echap" in by["echap-stalkerware"]
    assert by["stamus-lateral"].splitlines() == ["Copyright(C) 2015-2022, Stamus Networks", "Copyright 2026 Stamus Networks"]


def test_attribution_rules_and_filled_template_texts():
    from types import SimpleNamespace

    from suriharvest.release import _notice, filled_text, holders, missing_attribution, needs_attribution

    assert needs_attribution("MIT") and needs_attribution("BSD-3-Clause AND GPL-2.0-only") and needs_attribution(None)
    assert not needs_attribution("CC0-1.0")
    mit = filled_text("MIT", ["Copyright (c) 2023 Aleksi Bovellan"]).decode()
    assert mit.splitlines()[2] == "Copyright (c) 2023 Aleksi Bovellan" and "<year>" not in mit
    assert filled_text("GPL-3.0-only", ["x"]) is None and filled_text("MIT", []) is None
    cfg = SimpleNamespace(copyright="Copyright (c) 2023 Aleksi Bovellan", homepage=None)
    notices = {"n": [["Copyright (c) 2023 Aleksi Bovellan", "* Redistributions of source code must retain the above copyright notice"]]}
    assert holders("n", cfg, notices) == ["Copyright (c) 2023 Aleksi Bovellan"]
    rows = {
        "n": SimpleNamespace(licence="MIT", url="https://example.org/r.rules", redistribute="yes"),
        "c": SimpleNamespace(licence="CC0-1.0", url="https://example.org/c", redistribute="yes"),
    }
    assert missing_attribution(["n", "c"], rows, {"n": SimpleNamespace(copyright=None)}, {}) == ["n"]
    assert missing_attribution(["n", "c"], rows, {"n": cfg}, {}) == []
    text = _notice(["n"], rows, {"n": cfg}, {}, {"n": ["MIT"]})
    assert "`LICENSES/n/LICENSE.MIT.txt`" in text and "- Copyright (c) 2023 Aleksi Bovellan" in text
    assert "LICENSES/texts/MIT.txt" not in text


def test_git_sources_keep_their_licence_files_for_the_release(tmp_path, monkeypatch):
    """A git source keeps the LICENSE / NOTICE files of its repository root (or its declared licence_files):
    they ship in LICENSES/<source>/ (Apache NOTICE propagation) and their copyright lines count as holders."""
    import subprocess
    import tarfile

    import yaml

    from tests.fakes import ACCEPT_ALL, python_script
    from tests.test_pipeline import LOCAL_A, run, write

    repo = tmp_path / "upstream"
    write(repo / "rules" / "a.rules", LOCAL_A)
    write(repo / "LICENSE", "Apache License", "Version 2.0", "", "Copyright 2017 Example Detection Team")
    write(repo / "NOTICE", "Example Detections", "Copyright 2017 Example Detection Team")
    write(repo / "docs" / "LICENSE", "not kept: not at the root")
    write(repo / "README.md", "not rules")
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "one"], check=True)
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    run("init", str(root), "--engine", f"suricata-7={python_script(tmp_path / 'fake-suricata', ACCEPT_ALL)}")
    src = {"name": "up", "type": "git", "url": f"file://{repo}", "licence": "Apache-2.0", "redistribute": "yes"}
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": [src]}))
    monkeypatch.chdir(root)
    run("update")
    corpus = root / "corpus" / "up"
    assert (corpus / "LICENSE").is_file() and (corpus / "NOTICE").is_file() and not (corpus / "docs").exists()
    assert not (corpus / "README.md").exists()
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "0", "--no-gates")
    with tarfile.open(out / "LICENSES.tar.gz") as tf:
        names = set(tf.getnames())
        notice_file = tf.extractfile("LICENSES/up/NOTICE").read().decode()  # type: ignore[union-attr]
    assert {"LICENSES/up/LICENSE", "LICENSES/up/NOTICE", "LICENSES/texts/Apache-2.0.txt"} <= names
    assert "Example Detections" in notice_file
    assert "- Copyright 2017 Example Detection Team" in (out / "NOTICE.md").read_text()  # no copyright: field needed
    # upstream drops its NOTICE: the next sync removes it from the corpus
    (repo / "NOTICE").unlink()
    subprocess.run([*git, "commit", "-qam", "two"], check=True)
    run("update")
    assert not (corpus / "NOTICE").exists() and (corpus / "LICENSE").is_file()


def test_loose_rules_files_carry_licence_headers_and_source_sections(released, tmp_path):  # noqa: F811
    """Every loose .rules asset names the licences of its rules with links to their full texts (shipped as
    LICENSES.<id>.txt assets), NOTICE.md, LICENSES.tar.gz and the manifest. U4: the merged file is ordered by
    source with a marker line per source. U5: the modification notice names what changed and the build date."""
    out = tmp_path / "rel"
    run(
        "release",
        "build",
        str(out),
        "--engine",
        "suricata-7",
        "--build-epoch",
        "1763100000",
        "--download-base",
        "https://example.invalid/dl",
    )
    merged = (out / "suricata-7.rules").read_text()
    head = merged.split("# ---- source", 1)[0]
    assert "# Licences of the rules in this file" in head
    assert "MIT: full text https://example.invalid/dl/LICENSES.MIT.txt ; https://spdx.org/licenses/MIT.html" in head
    assert "https://example.invalid/dl/NOTICE.md" in head and "https://example.invalid/dl/LICENSES.tar.gz" in head
    assert "https://example.invalid/dl/manifest.jsonl.gz" in head and "2025-11-14" in head
    assert (out / "LICENSES.MIT.txt").read_text().startswith("MIT License")
    assert "LICENSES.MIT.txt" in (out / "SHA256SUMS").read_text()
    # sections: one marker per source, in source order, each followed by that source's rules only
    markers = [x for x in merged.splitlines() if x.startswith("# ---- source ")]
    assert [m.split()[3] for m in markers] == ["et", "repoA"] and all("(MIT)" in m for m in markers)
    for src in ("et", "repoA"):
        own = [x for x in (out / f"suricata-7.by-source.{src}.rules").read_text().splitlines() if x and not x.startswith("#")]
        section = merged.split(f"# ---- source {src} ", 1)[1].split("\n", 1)[1].split("# ---- source", 1)[0]
        assert [x for x in section.splitlines() if x] == own
    by_et = (out / "suricata-7.by-source.et.rules").read_text()
    assert "# Licences of the rules in this file" in by_et and "LICENSES.MIT.txt" in by_et
    assert "build 2025-11-14" in by_et or "on 2025-11-14" in by_et
    assert "Copyright (c) 2026 Test Publisher" in by_et  # the catalog / sources.yaml copyright line
    notice = (out / "NOTICE.md").read_text()
    assert "Changes suriharvest made to rule text (build 2025-11-14T" in notice and "collisions.json" in notice
    assert "not applied to a release build" in notice and "that is the only change" not in notice
    assert "Rule text as published" in notice or "Changed by suriharvest" in notice
    # the tarball carries the same merged file
    import tarfile

    with tarfile.open(out / "suriharvest-7.tar.gz") as tf:
        assert tf.extractfile("rules/suricata.rules").read().decode() == merged  # type: ignore[union-attr]


def test_changes_line_counts_remaps_and_dataset_rewrites():
    from suriharvest.release import _changes_line

    line = _changes_line("2026-11-14T00:00:00Z", {"a": 2}, {"a": 1, "b": 5}, ["a"])
    assert line.startswith("# Changed by suriharvest on 2026-11-14: 2 sid(s) remapped (collisions.json), 1 dataset load path(s)")
    assert _changes_line("2026-11-14T00:00:00Z", {}, {}, ["a"]).startswith("# Rule text as published; build 2026-11-14")


def test_package_metadata_declares_the_bundled_fonts_licence():
    """The wheel ships OFL fonts, so the licence expression and licence files name them; NOTICE lists the
    bundled third-party material (fonts, sid allocation table)."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    fonts = sorted((root / "src" / "suriharvest" / "web" / "static" / "fonts").glob("*-OFL.txt"))
    assert fonts and "OFL-1.1" in project["license"]
    assert all(any(Path(f).match(pat) for pat in project["license-files"]) for f in [str(x.relative_to(root)) for x in fonts])
    notice = (root / "NOTICE").read_text()
    assert "SIL Open Font License" in notice and "sidallocation.org" in notice


def test_licence_text_copyright_is_not_a_rules_holder():
    """A publisher's gpl-2.0.txt carries the FSF's copyright on the licence text; a commented LICENSE file has
    '#  Copyright' lines: neither must show up as (or duplicate) a holder."""
    blocks = [["#  Copyright (c) 2003-2026, Emerging Threats"], ["Copyright (C) 1989, 1991 Free Software Foundation, Inc.,"]]
    assert copyright_lines(blocks) == ["Copyright (c) 2003-2026, Emerging Threats"]


def test_rule_licences_label_each_rule_of_a_split_licence_source(ws, tmp_path):  # noqa: F811
    """A source whose licence splits by sid (ET Open: GPL-2 for the old Snort GPL rules, BSD otherwise) labels
    every rule in the manifest with its own licence; sources without rule_licences keep the source licence."""
    import json

    import pytest
    import yaml

    from suriharvest.config import ConfigError, SourceConfig, catalog_sources

    data = yaml.safe_load((ws / "sources.yaml").read_text())
    et = next(x for x in data["sources"] if x["name"] == "et")
    et["licence"] = "BSD-3-Clause AND GPL-2.0-only"
    et["rule_licences"] = [{"licence": "GPL-2.0-only", "sids": "1-3464, 2000003", "msg_prefix": "GPL "}, {"licence": "BSD-3-Clause"}]
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    run("sync")
    run("export", "source:et,repoB", "--out", str(tmp_path / "e"), "--unit", "logic", "--remap-colliding-sids")
    rows = [json.loads(x) for x in (tmp_path / "e" / "manifest.jsonl").read_text().splitlines()]
    lic = {(r["source"], r["sid"]): r["licence"] for r in rows}
    assert lic[("et", 2000003)] == "GPL-2.0-only"
    assert {v for (s, sid), v in lic.items() if s == "et" and sid != 2000003} == {"BSD-3-Clause"}
    assert {v for (s, _), v in lic.items() if s == "repoB"} == {"GPL-3.0"}
    cfg = SourceConfig(name="x", type="local", url=".", licence="L", rule_licences=[{"licence": "A", "msg_prefix": "GPL "}])
    assert cfg.licence_of(5, "GPL EXPLOIT x") == "A" and cfg.licence_of(5, "ET x") == "L"
    with pytest.raises(ConfigError):
        SourceConfig(name="x", type="local", url=".", rule_licences=[{"licence": "A", "sids": "one-two"}])
    et_open = next(c for c in catalog_sources() if c.name == "et-open")
    assert et_open.licence_of(2100498, "GPL ATTACK_RESPONSE id check") == "GPL-2.0-only"
    assert et_open.licence_of(2024897, "ET MALWARE x") == "BSD-3-Clause"


def test_combined_licence_and_catalog_homepages():
    """Index.yaml carries one SPDX expression; a catalog URL with ${suricata_version} has a homepage, so NOTICE.md
    never shows the raw template."""
    from suriharvest.config import catalog_sources
    from suriharvest.release import combined_licence

    assert combined_licence(["BSD-3-Clause AND GPL-2.0-only", "MIT", "GPL-3.0-only", "MIT"]) == (
        "BSD-3-Clause AND GPL-2.0-only AND GPL-3.0-only AND MIT"
    )
    assert combined_licence(["MIT OR Apache-2.0", "MIT"]) == "(MIT OR Apache-2.0) AND MIT"
    assert combined_licence(["MIT", None]) == "Various" and combined_licence(["see README"]) == "Various"
    templated = [c.name for c in catalog_sources() if "${" in c.url and not c.homepage]
    assert templated == []


def test_every_licence_of_a_published_catalog_source_has_its_text_bundled():
    """The text of each licence travels with its rules; a missing text stops the release build."""
    from types import SimpleNamespace

    from suriharvest.config import catalog_sources
    from suriharvest.release import licence_text, missing_licence_texts, spdx_ids

    published = {c.name: c for c in catalog_sources() if c.redistribute == "yes"}
    assert missing_licence_texts(published, published) == []
    for spdx in ("AGPL-3.0-only", "AGPL-3.0-or-later", "LGPL-3.0-only", "EUPL-1.2", "Unlicense"):
        assert licence_text(spdx), spdx
    fake = {"x": SimpleNamespace(licence="BSD-3-Clause-Clear"), "y": SimpleNamespace(licence="MIT AND GPL-2.0-or-later")}
    assert missing_licence_texts(fake, fake) == ["x: BSD-3-Clause-Clear"]
    assert spdx_ids("LGPL-3.0-only") == ["LGPL-3.0-only"]
