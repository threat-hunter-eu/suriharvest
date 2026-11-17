"""Validators used by accept.sh. Run with the installed tool's interpreter (it has PyYAML): python -I checks.py CMD ...

Each command prints one short line (the evidence) and exits 0 on success, 1 on a failed check, 2 on usage errors.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - the tool envs all ship PyYAML
    yaml = None

RULE_EXT = (".yml", ".yaml")
TRACEBACK = re.compile(r"Traceback \(most recent call last\)|Internal Server Error|jinja2\.exceptions|UndefinedError")


def fail(msg: str) -> None:
    print(msg)
    sys.exit(1)


# ------------------------------------------------------------------------------------------------- sigma


def _sigma_docs(name: str, data: bytes) -> tuple[list[dict], str | None]:
    """Parse one exported file. Returns (rule documents, error)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        return [], f"{name}: not UTF-8 ({e})"
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as e:
        return [], f"{name}: YAML error: {str(e).splitlines()[0]}"
    out = []
    for d in docs:
        if not isinstance(d, dict):
            return [], f"{name}: a document is not a mapping"
        if "title" not in d or not ("detection" in d or "correlation" in d or "filter" in d):
            return [], f"{name}: not a Sigma rule (needs title + detection/correlation/filter)"
        out.append(d)
    return out, None


def _report_sigma(items: list[tuple[str, bytes]], args: argparse.Namespace, what: str) -> None:
    rules, errors, files = [], [], 0
    for name, data in items:
        if not name.endswith(RULE_EXT):
            continue
        files += 1
        docs, err = _sigma_docs(name, data)
        if err:
            errors.append(err)
        rules.extend(docs)
    titles = {str(d.get("title")) for d in rules}
    if errors:
        fail(f"{what}: {len(errors)} bad file(s): " + "; ".join(errors[:3]))
    n = len(rules)
    if args.min is not None and n < args.min:
        fail(f"{what}: {n} rule documents in {files} files, expected at least {args.min}")
    if args.max is not None and n > args.max:
        fail(f"{what}: {n} rule documents in {files} files, expected at most {args.max}")
    for t in args.title or []:
        if t not in titles:
            fail(f"{what}: rule titled {t!r} missing (have: {sorted(titles)[:8]})")
    for t in args.no_title or []:
        if t in titles:
            fail(f"{what}: rule titled {t!r} should not be there")
    if args.correlation_complete:
        names = {d.get("name") for d in rules if d.get("name")} | {str(d.get("id")) for d in rules}
        for d in rules:
            corr = d.get("correlation")
            if isinstance(corr, dict):
                missing = [r for r in corr.get("rules") or [] if r not in names]
                if missing:
                    fail(f"{what}: correlation {d.get('title')!r} references rules not exported: {missing}")
    print(f"{what}: {n} Sigma rule documents in {files} files, all parse")


def cmd_sigma_dir(args: argparse.Namespace) -> None:
    root = Path(args.path)
    if not root.is_dir():
        fail(f"{root}: not a folder")
    items = [(str(p.relative_to(root)), p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file()]
    _report_sigma(items, args, str(root))


def cmd_sigma_zip(args: argparse.Namespace) -> None:
    p = Path(args.path)
    if not zipfile.is_zipfile(p):
        fail(f"{p}: not a zip file")
    with zipfile.ZipFile(p) as z:
        bad = z.testzip()
        if bad:
            fail(f"{p}: CRC error in {bad}")
        for n in z.namelist():
            if n.startswith("/") or ".." in Path(n).parts:
                fail(f"{p}: unsafe member path {n!r}")
        items = [(n, z.read(n)) for n in z.namelist() if not n.endswith("/")]
    _report_sigma(items, args, str(p))


# ------------------------------------------------------------------------------------------------- tabular


def cmd_jsonl(args: argparse.Namespace) -> None:
    p = Path(args.path)
    if not p.is_file():
        fail(f"{p}: missing")
    rows = []
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as e:
            fail(f"{p}:{i}: invalid JSON: {e}")
    keys = [k for k in (args.keys or "").split(",") if k]
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict):
            fail(f"{p}:{i}: not an object")
        missing = [k for k in keys if not any(alt in r for alt in k.split("|"))]
        if missing:
            fail(f"{p}:{i}: missing keys {missing} (has {sorted(r)[:15]})")
    if args.min is not None and len(rows) < args.min:
        fail(f"{p}: {len(rows)} rows, expected at least {args.min}")
    print(f"{p.name}: {len(rows)} JSON rows" + (f" with {keys}" if keys else ""))


def cmd_csv(args: argparse.Namespace) -> None:
    p = Path(args.path)
    if not p.is_file():
        fail(f"{p}: missing")
    text = p.read_text(encoding="utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text)))
    cols = [c for c in (args.cols or "").split(",") if c]
    header = rows[0].keys() if rows else next(csv.reader(io.StringIO(text)), [])
    missing = [c for c in cols if not any(alt in header for alt in c.split("|"))]
    if missing:
        fail(f"{p}: missing columns {missing} (header {list(header)[:15]})")
    if args.min is not None and len(rows) < args.min:
        fail(f"{p}: {len(rows)} rows, expected at least {args.min}")
    for r in rows:  # formula injection guard (spreadsheet export)
        for v in r.values():
            if isinstance(v, str) and v[:1] in ("=", "+", "@") and not v.startswith("=="):
                fail(f"{p}: cell starts with {v[:1]!r} (CSV formula injection): {v[:60]!r}")
    print(f"{p.name}: {len(rows)} CSV rows, columns ok")


def cmd_nonempty(args: argparse.Namespace) -> None:
    p = Path(args.path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = [f for f in p.rglob("*") if f.is_file()]
    else:
        fail(f"{p}: missing")
    size = sum(f.stat().st_size for f in files)
    if size < args.min_bytes:
        fail(f"{p}: {len(files)} file(s), {size} bytes (expected >= {args.min_bytes})")
    text = b"".join(f.read_bytes()[:200000] for f in files[:200]).decode("utf-8", "replace")
    if TRACEBACK.search(text):
        fail(f"{p}: contains a Python traceback")
    for needle in args.contains or []:
        if needle not in text:
            fail(f"{p}: does not contain {needle!r}")
    print(f"{p}: {len(files)} file(s), {size} bytes")


# ------------------------------------------------------------------------------------------------- json


def _walk(obj, path: str):  # type: ignore[no-untyped-def]
    for part in [x for x in path.split(".") if x]:
        alts = part.split("|")
        for alt in alts:
            if isinstance(obj, list) and alt.lstrip("-").isdigit() and -len(obj) <= int(alt) < len(obj):
                obj = obj[int(alt)]
                break
            if isinstance(obj, dict) and alt in obj:
                obj = obj[alt]
                break
        else:
            raise KeyError(part)
    return obj


def cmd_json(args: argparse.Namespace) -> None:
    raw = Path(args.path).read_text(encoding="utf-8") if args.path != "-" else sys.stdin.read()
    # Some CLIs print a banner line before the JSON: take from the first { or [.
    start = min([i for i in (raw.find("{"), raw.find("[")) if i >= 0], default=0)
    try:
        data = json.loads(raw[start:])
    except json.JSONDecodeError as e:
        fail(f"not JSON: {e}: {raw[:200]!r}")
    try:
        val = _walk(data, args.expr)
    except KeyError as e:
        fail(f"no {args.expr} in JSON (stuck at {e}); top-level keys: {list(data)[:12] if isinstance(data, dict) else type(data).__name__}")
    if args.len:
        val = len(val)
    print(val if not isinstance(val, (dict, list)) else json.dumps(val)[:2000])


def cmd_json_count(args: argparse.Namespace) -> None:
    """Count items of a JSON list (at EXPR) whose FIELD is truthy (or equals --value)."""
    raw = Path(args.path).read_text(encoding="utf-8")
    start = min([i for i in (raw.find("{"), raw.find("[")) if i >= 0], default=0)
    try:
        items = _walk(json.loads(raw[start:]), args.expr)
    except (json.JSONDecodeError, KeyError) as e:
        fail(f"cannot read {args.expr}: {e}")
    n = sum(1 for it in items if (str(it.get(args.field)) == args.value if args.value is not None else bool(it.get(args.field))))
    print(n)


def cmd_jsonl_differ(args: argparse.Namespace) -> None:
    """Count JSONL rows where field A is set and differs from field B (e.g. exported_sid vs sid)."""
    n = 0
    for line in Path(args.path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            d = json.loads(line)
            if d.get(args.a) not in (None, "") and d.get(args.a) != d.get(args.b):
                n += 1
    print(n)


# ------------------------------------------------------------------------------------------------- suricata


def count_rules(path: Path) -> tuple[int, int]:
    active = disabled = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if re.match(r"^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth|config)\s", s):
            active += 1
        elif re.match(r"^#+\s*(alert|drop|pass|reject)\s.*\bsid\s*:", s):
            disabled += 1
    return active, disabled


def cmd_suricata_test(args: argparse.Namespace) -> None:
    rules = Path(args.path).resolve()
    if not rules.is_file():
        fail(f"{rules}: missing")
    binary = shutil.which(args.suricata) or args.suricata
    active, disabled = count_rules(rules)
    with tempfile.TemporaryDirectory() as logdir:
        cmd = [binary, "-T", "-v", "-c", args.config, "-S", str(rules), "-l", logdir, "--set", f"default-rule-path={rules.parent}"]
        if args.threshold_file:
            cmd += ["--set", f"threshold-file={Path(args.threshold_file).resolve()}"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            fail(f"suricata not found ({binary})")
    out = p.stdout + p.stderr
    m = re.search(r"(\d+) rules successfully loaded, (\d+) rules failed", out)
    errors = [l for l in out.splitlines() if re.match(r"^(E: |Error: |\[ERRCODE)", l.strip())]
    loaded, failed = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    if active == 0 and args.allow_empty:
        print(f"{rules.name}: no active rules (allowed)")
        return
    problems = []
    if p.returncode != 0:
        problems.append(f"suricata -T exit {p.returncode}")
    if failed:
        problems.append(f"{failed} rules failed")
    if errors:
        problems.append(f"{len(errors)} error lines, first: {errors[0][:220]}")
    if loaded is None:
        problems.append("no 'rules successfully loaded' line")
    if args.expect_loaded is not None and loaded != args.expect_loaded:
        problems.append(f"loaded {loaded}, expected {args.expect_loaded}")
    if loaded is not None and loaded != active:
        problems.append(f"loaded {loaded} but the file has {active} active rules (silently dropped?)")
    if args.threshold_file:
        bad = [l for l in out.splitlines() if re.search(r"threshold|suppress", l, re.I) and re.search(r"error|fail|invalid", l, re.I)]
        if bad:
            problems.append(f"threshold file: {bad[0][:220]}")
    if problems:
        fail(f"{rules.name}: " + "; ".join(problems))
    extra = f", threshold file {Path(args.threshold_file).name} accepted" if args.threshold_file else ""
    print(f"{rules.name}: {loaded} rules loaded, 0 failed, {disabled} commented out (suricata -T){extra}")


def _active_lines(path: Path) -> list[str]:
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if re.match(r"^(alert|drop|pass|reject\w*)\s", l.strip())]


def cmd_rule_line(args: argparse.Namespace) -> None:
    """The active rule(s) of a sid in a rules file: present or absent, action, text it must (not) contain."""
    path = Path(args.path)
    if not path.is_file():
        fail(f"{path}: missing")
    lines = [l for l in _active_lines(path) if re.search(rf"\bsid\s*:\s*{args.sid}\s*;", l)]
    if args.absent:
        if lines:
            fail(f"{path.name}: sid {args.sid} should not be active: {lines[0][:200]}")
        print(f"{path.name}: sid {args.sid} not active")
        return
    if not lines:
        fail(f"{path.name}: no active rule with sid {args.sid}")
    if args.count is not None and len(lines) != args.count:
        fail(f"{path.name}: {len(lines)} active rules with sid {args.sid}, expected {args.count}")
    line = lines[0]
    if args.action and not line.startswith(args.action + " "):
        fail(f"{path.name}: sid {args.sid} action is {line.split()[0]!r}, expected {args.action!r}: {line[:200]}")
    for s in args.contains or []:
        if s not in line:
            fail(f"{path.name}: sid {args.sid} lacks {s!r}: {line[:240]}")
    for s in args.lacks or []:
        if s in line:
            fail(f"{path.name}: sid {args.sid} contains {s!r}: {line[:240]}")
    print(f"{path.name}: {line[:160]}")


def cmd_comment_continuations(args: argparse.Namespace) -> None:
    """Comment lines ending in a backslash: Suricata joins the next line to them, so the next rule is lost."""
    bad = []
    for f in args.paths:
        lines = Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
        for i, l in enumerate(lines):
            if l.lstrip().startswith("#") and l.rstrip().endswith("\\"):
                nxt = lines[i + 1] if i + 1 < len(lines) else ""
                bad.append(f"{Path(f).name}:{i + 1}: {l.strip()[:80]!r} then {nxt.strip()[:60]!r}")
    if bad:
        fail(f"{len(bad)} comment line(s) end in a backslash: " + "; ".join(bad[:3]))
    print(f"{len(args.paths)} file(s): no comment line ends in a backslash")


def cmd_interrupt(args: argparse.Namespace) -> None:
    """Start CMD in its own process group, SIGKILL the group as soon as SQL (on the workspace DB) returns a non-zero
    count: a deterministic "killed mid-update". Fails if CMD finishes first."""
    import signal
    import sqlite3
    import time

    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    p = subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t0 = time.monotonic()
    while time.monotonic() - t0 < args.timeout:
        if p.poll() is not None:
            out = p.stdout.read().decode("utf-8", "replace") if p.stdout else ""
            fail(f"the command finished (exit {p.returncode}) before it could be interrupted; last output: {out[-300:]!r}")
        n = 0
        if Path(args.db).exists():
            try:
                c = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=0.05)
                n = c.execute(args.sql).fetchone()[0]
                c.close()
            except sqlite3.Error:
                n = 0
        if n:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            out = p.stdout.read().decode("utf-8", "replace") if p.stdout else ""
            print(out[-2000:])
            print(f"killed (SIGKILL, whole process group) after {time.monotonic() - t0:.2f}s")
            return
        time.sleep(0.01)
    os.killpg(p.pid, signal.SIGKILL)
    fail(f"condition never met in {args.timeout}s: {args.sql}")


def cmd_archive(args: argparse.Namespace) -> None:
    """Members of a zip / tar archive: --has NAME (exact or prefix ending in /), --min N members."""
    import tarfile

    path = Path(args.path)
    if zipfile.is_zipfile(path):
        z = zipfile.ZipFile(path)
        names = z.namelist()
        read = lambda n: z.read(n)  # noqa: E731
    else:
        tf = tarfile.open(path)
        names = [m.name for m in tf.getmembers()]
        read = lambda n: tf.extractfile(n).read()  # noqa: E731
    for h in args.has or []:
        if not any(n == h or (h.endswith("/") and n.startswith(h)) or n.endswith("/" + h) for n in names):
            fail(f"{path.name}: no member {h!r}; members: {names[:20]}")
    for spec in args.grep or []:
        member, _, needle = spec.partition("=")
        hits = [n for n in names if n == member or n.endswith("/" + member)]
        if not hits:
            fail(f"{path.name}: no member {member!r}")
        if needle not in read(hits[0]).decode("utf-8", "replace"):
            fail(f"{path.name}: {hits[0]} does not contain {needle!r}")
    print(f"{path.name}: {len(names)} members")


def cmd_yaml_add(args: argparse.Namespace) -> None:
    """Append entries (a JSON list) to list KEY of a YAML mapping file (profile overrides)."""
    p = Path(args.path)
    data = (yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else None) or {}
    if not isinstance(data, dict):
        fail(f"{p}: not a mapping")
    data.setdefault(args.key, [])
    data[args.key] = (data[args.key] or []) + json.loads(args.entries)
    p.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"{p.name}: {args.key} has {len(data[args.key])} entries")


def cmd_rules_count(args: argparse.Namespace) -> None:
    active, disabled = count_rules(Path(args.path))
    if args.expect is not None and active != args.expect:
        fail(f"{args.path}: {active} active rules, expected {args.expect}")
    if args.min is not None and active < args.min:
        fail(f"{args.path}: {active} active rules, expected at least {args.min}")
    sids = re.findall(r"\bsid\s*:\s*(\d+)", Path(args.path).read_text(encoding="utf-8", errors="replace"))
    for s in args.has_sid or []:
        if s not in sids:
            fail(f"{args.path}: sid {s} missing")
    for s in args.no_sid or []:
        if s in sids:
            fail(f"{args.path}: sid {s} should not be there")
    if args.unique_sids:
        text = Path(args.path).read_text(encoding="utf-8", errors="replace")
        pairs = re.findall(r"^(?!#)[^\n]*?\bsid\s*:\s*(\d+)", text, flags=re.M)
        from collections import Counter

        dupes = sorted(s for s, n in Counter(pairs).items() if n > 1)
        if dupes:
            fail(f"{args.path}: duplicate sids among active rules: {dupes[:10]}")
    print(f"{Path(args.path).name}: {active} active, {disabled} commented-out rules")


# ------------------------------------------------------------------------------------------------- web


def cmd_http(args: argparse.Namespace) -> None:
    req = urllib.request.Request(args.url, headers={"User-Agent": "acceptance-harness"})
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as r:  # noqa: S310 - loopback test URL
            status, headers, body = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, e.headers, e.read()
    except (urllib.error.URLError, OSError) as e:
        fail(f"GET {args.url}: {e}")
    text = body.decode("utf-8", "replace")
    ctype = headers.get("Content-Type", "")
    problems = []
    if status != args.status:
        problems.append(f"HTTP {status} (expected {args.status})")
    if TRACEBACK.search(text):
        problems.append("traceback/template error in body")
    if not headers.get("Content-Security-Policy"):
        problems.append("no Content-Security-Policy header")
    if status != 200:
        pass
    elif args.kind == "json":
        if "json" not in ctype:
            problems.append(f"content-type {ctype!r}, expected JSON")
        else:
            try:
                json.loads(text)
            except json.JSONDecodeError as e:
                problems.append(f"invalid JSON: {e}")
    elif args.kind == "html" and "html" not in ctype:
        problems.append(f"content-type {ctype!r}, expected HTML")
    if args.kind == "html" and status == 200 and re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", text):
        problems.append("inline <script> (breaks script-src 'self')")
    if problems:
        fail(f"GET {args.url}: " + "; ".join(problems) + f"; body: {text[:160]!r}")
    if args.save:
        Path(args.save).write_bytes(body)
    print(f"GET {args.url}: {status} {ctype.split(';')[0]}, {len(body)} bytes, CSP present")


# ------------------------------------------------------------------------------------------------- workspace


def cmd_sources(args: argparse.Namespace) -> None:
    data = yaml.safe_load(Path(args.path).read_text(encoding="utf-8")) or {}
    items = data.get("sources", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        fail(f"{args.path}: no source list")
    keep = set(args.keep.split(",")) if args.keep else set()
    names = [s["name"] for s in items if isinstance(s, dict) and (not args.enabled or s.get("enabled", True))]
    print(" ".join(n for n in names if n not in keep))


def main() -> None:
    if yaml is None:
        print("PyYAML missing in this interpreter")
        sys.exit(2)
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("sigma-dir", cmd_sigma_dir), ("sigma-zip", cmd_sigma_zip)):
        p = sub.add_parser(name)
        p.add_argument("path")
        p.add_argument("--min", type=int)
        p.add_argument("--max", type=int)
        p.add_argument("--title", action="append")
        p.add_argument("--no-title", action="append")
        p.add_argument("--correlation-complete", action="store_true")
        p.set_defaults(fn=fn)
    p = sub.add_parser("jsonl")
    p.add_argument("path")
    p.add_argument("--min", type=int)
    p.add_argument("--keys")
    p.set_defaults(fn=cmd_jsonl)
    p = sub.add_parser("csv")
    p.add_argument("path")
    p.add_argument("--min", type=int)
    p.add_argument("--cols")
    p.set_defaults(fn=cmd_csv)
    p = sub.add_parser("nonempty")
    p.add_argument("path")
    p.add_argument("--min-bytes", type=int, default=1)
    p.add_argument("--contains", action="append")
    p.set_defaults(fn=cmd_nonempty)
    p = sub.add_parser("json")
    p.add_argument("path")
    p.add_argument("expr")
    p.add_argument("--len", action="store_true")
    p.set_defaults(fn=cmd_json)
    p = sub.add_parser("json-count")
    p.add_argument("path")
    p.add_argument("expr")
    p.add_argument("field")
    p.add_argument("--value")
    p.set_defaults(fn=cmd_json_count)
    p = sub.add_parser("jsonl-differ")
    p.add_argument("path")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(fn=cmd_jsonl_differ)
    p = sub.add_parser("suricata-test")
    p.add_argument("path")
    p.add_argument("--expect-loaded", type=int)
    p.add_argument("--config", default=os.environ.get("SURICATA_CONFIG", "/etc/suricata/suricata.yaml"))
    p.add_argument("--suricata", default=os.environ.get("SURICATA", "suricata"))
    p.add_argument("--allow-empty", action="store_true")
    p.add_argument("--threshold-file")
    p.set_defaults(fn=cmd_suricata_test)
    p = sub.add_parser("rule-line")
    p.add_argument("path")
    p.add_argument("sid")
    p.add_argument("--action")
    p.add_argument("--contains", action="append")
    p.add_argument("--lacks", action="append")
    p.add_argument("--count", type=int)
    p.add_argument("--absent", action="store_true")
    p.set_defaults(fn=cmd_rule_line)
    p = sub.add_parser("comment-continuations")
    p.add_argument("paths", nargs="+")
    p.set_defaults(fn=cmd_comment_continuations)
    p = sub.add_parser("interrupt")
    p.add_argument("db")
    p.add_argument("sql")
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("cmd", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_interrupt)
    p = sub.add_parser("archive")
    p.add_argument("path")
    p.add_argument("--has", action="append")
    p.add_argument("--grep", action="append", help="MEMBER=TEXT")
    p.set_defaults(fn=cmd_archive)
    p = sub.add_parser("yaml-add")
    p.add_argument("path")
    p.add_argument("key")
    p.add_argument("entries")
    p.set_defaults(fn=cmd_yaml_add)
    p = sub.add_parser("rules-count")
    p.add_argument("path")
    p.add_argument("--expect", type=int)
    p.add_argument("--min", type=int)
    p.add_argument("--has-sid", action="append")
    p.add_argument("--no-sid", action="append")
    p.add_argument("--unique-sids", action="store_true")
    p.set_defaults(fn=cmd_rules_count)
    p = sub.add_parser("http")
    p.add_argument("url")
    p.add_argument("--kind", choices=("html", "json", "any"), default="html")
    p.add_argument("--timeout", type=float, default=60)
    p.add_argument("--status", type=int, default=200)
    p.add_argument("--save")
    p.set_defaults(fn=cmd_http)
    p = sub.add_parser("sources")
    p.add_argument("path")
    p.add_argument("--enabled", action="store_true")
    p.add_argument("--keep", default="")
    p.set_defaults(fn=cmd_sources)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
