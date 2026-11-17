"""Regular expressions written by the user (rule_regex / msg_regex selectors, suricata-update `re:` lines) run over
rule text that comes from upstream sources.

Python's `re` backtracks: a pattern like `ET.*trojan.*cnc` is quadratic on a long line, and rule lines of up to
256 KiB are accepted at ingest, so one hostile rule could stall every build for minutes. Two limits apply:

- the pattern sees at most the first MAX_SCAN bytes of a text. Suricata's own rule size limit is 8 KiB (a longer
  line fails with `no terminating ";" found`), so a longer rule never loads anyway; the cap is the same with or
  without RE2, so a build selects the same rules on every machine;
- when google-re2 is installed (`pip install google-re2`, optional), patterns it can compile run in linear time.
  Patterns RE2 does not support (back-references, look-arounds) use Python's `re` on the capped text.
"""

from __future__ import annotations

import re
from typing import Any

MAX_SCAN = 8192

try:  # optional: linear-time matching
    import re2 as _re2  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on the environment
    _re2 = None


def _fast(pattern: str, flags: int) -> Any | None:
    if _re2 is None or flags & ~re.IGNORECASE:
        return None
    try:
        opts = _re2.Options()
        opts.log_errors = False
        opts.case_sensitive = not flags & re.IGNORECASE
        return _re2.compile(pattern, opts)
    except Exception:  # noqa: BLE001 - RE2 refuses back-references, look-arounds ...: Python's re (capped) does the work
        return None


class UserRegex:
    """A user pattern with a bounded cost per text. `search` returns True/False."""

    __slots__ = ("_py", "_re2", "pattern")

    def __init__(self, pattern: str, flags: int = re.IGNORECASE) -> None:
        self.pattern = pattern
        self._py = re.compile(pattern, flags)  # raises re.error: the syntax users write is Python's
        self._re2 = _fast(pattern, flags)

    @property
    def linear(self) -> bool:
        return self._re2 is not None

    def search(self, text: str) -> bool:
        t = text[:MAX_SCAN]
        if self._re2 is not None:
            return self._re2.search(t) is not None
        return self._py.search(t) is not None


def compile_user(pattern: str, flags: int = re.IGNORECASE) -> UserRegex:
    return UserRegex(pattern, flags)
