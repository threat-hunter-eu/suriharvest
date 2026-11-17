"""Triage verdicts: keep / review / drop on a logic hash, a rule key or a source. An overlay:
nothing is deleted, and the verdict is re-applied after every index rebuild."""

from __future__ import annotations

from sqlalchemy.orm import Session

from suriharvest.index import apply_verdict_for
from suriharvest.models import Verdict, utcnow

VERDICTS = ("keep", "review", "drop")
SCOPES = ("logic", "rule", "source")


class TriageError(ValueError):
    pass


def set_verdict(s: Session, scope: str, key: str, verdict: str, note: str | None = None) -> int:
    """Set (or with verdict 'clear', remove) a verdict. Returns the number of logic groups it touched."""
    if scope not in SCOPES or verdict not in (*VERDICTS, "clear"):
        raise TriageError("verdict must be keep|review|drop|clear and scope logic|rule|source")
    row = s.get(Verdict, (scope, key))
    if verdict == "clear":
        if row is not None:
            s.delete(row)
    elif row is None:
        s.add(Verdict(scope=scope, key=key, verdict=verdict, note=note))
    else:
        row.verdict, row.note, row.updated_at = verdict, note if note is not None else row.note, utcnow()
    s.commit()
    return apply_verdict_for(s, scope, key)
