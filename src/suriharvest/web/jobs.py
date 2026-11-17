"""Background jobs for the web UI: update, download one source, build.

One job at a time per server; each holds the workspace lock while it runs, so a CLI update or a timer run and a
web job never overlap (the second one reports "busy"). Output lines are kept in memory for the job page, which
polls /api/jobs/<id>. Rich markup is stripped.
"""

from __future__ import annotations

import re
import threading
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from rich.errors import MarkupError
from rich.text import Text

MARKUP = re.compile(r"\[/?[a-z ]*\]")


@dataclass
class Job:
    id: str
    kind: str
    title: str
    status: str = "running"  # running | done | failed
    started: datetime = field(default_factory=datetime.now)
    finished: datetime | None = None
    lines: list[str] = field(default_factory=list)
    result: dict[str, Any] = field(default_factory=dict)
    link: str | None = None  # where to go when it is done

    def say(self, text: str) -> None:
        try:  # rich's own parser, so escaped brackets (rich.markup.escape) come out as plain brackets
            plain = Text.from_markup(str(text)).plain
        except MarkupError:
            plain = MARKUP.sub("", str(text))
        for line in plain.splitlines() or [""]:
            self.lines.append(f"{datetime.now():%H:%M:%S}  {line}")
        del self.lines[:-2000]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "started": self.started.isoformat(timespec="seconds"),
            "finished": self.finished.isoformat(timespec="seconds") if self.finished else None,
            "lines": self.lines[-400:],
            "result": self.result,
            "link": self.link,
        }


class Busy(RuntimeError):
    pass


class Jobs:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.jobs: dict[str, Job] = {}
        self.order: list[str] = []

    def current(self) -> Job | None:
        for jid in reversed(self.order):
            if self.jobs[jid].status == "running":
                return self.jobs[jid]
        return None

    def recent(self, n: int = 10) -> list[Job]:
        return [self.jobs[j] for j in reversed(self.order[-n:])]

    def start(self, kind: str, title: str, fn: Callable[[Job], None], link: str | None = None) -> Job:
        with self._lock:
            running = self.current()
            if running is not None:
                raise Busy(f"{running.title} is still running")
            job = Job(uuid.uuid4().hex[:12], kind, title, link=link)
            self.jobs[job.id] = job
            self.order.append(job.id)
            del self.order[:-50]

        def run() -> None:
            try:
                fn(job)
                if job.status == "running":
                    job.status = "done"
            except Exception as e:  # noqa: BLE001 - every failure is shown on the job page
                job.status = "failed"
                job.say(f"failed: {type(e).__name__}: {e}")
                job.say(traceback.format_exc(limit=4))
            finally:
                job.finished = datetime.now()

        threading.Thread(target=run, name=f"suriharvest-job-{job.id}", daemon=True).start()
        return job
