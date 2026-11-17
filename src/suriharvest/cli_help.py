"""Terminal help as docs/conventions.md describes it (shared with sigharvest): the root commands grouped in panels
(Start here, Rules, Sources, Publish, Admin), one-sentence summaries, an example in the first panel, and option help
written as sentences (a capital letter and a full stop)."""

from __future__ import annotations

import re
from typing import Any

from typer.core import TyperGroup

PANELS: dict[str, tuple[str, ...]] = {
    "Start here": ("init", "update", "serve", "doctor"),
    "Rules": ("search", "show", "export", "profile", "triage", "deps"),
    "Sources": ("sources", "sync", "index", "validate", "stats"),
    "Publish": ("release", "site"),
    "Admin": ("runs", "quarantine", "version"),
}
OTHER = "Other"

START_EXAMPLES = {
    "init": "suriharvest init ~/suricata-rules",
    "update": "suriharvest update",
    "serve": "suriharvest serve",
    "doctor": "suriharvest doctor",
}

SUMMARIES = {
    "init": "Create a workspace.",
    "update": "Download rule changes, validate, index and rebuild the profiles.",
    "serve": "Start the web interface.",
    "doctor": "Check workspace health and the Suricata engines.",
    "search": "Find rules by words or filters.",
    "show": "Read a rule, its copies, revisions and validation results.",
    "export": "Save rules to a suricata.rules file or a suricata-update layout.",
    "profile": "Build your own ruleset: exclusions, overrides, builds and diffs.",
    "triage": "Mark a rule, logic or source as keep, review or drop.",
    "deps": "List flowbits nobody sets and files rules need.",
    "sources": "Choose where your rules come from.",
    "sync": "Download rule changes from your sources (no validation).",
    "index": "Refresh families, scores and search from stored rules.",
    "validate": "Check that rules load in each Suricata engine.",
    "stats": "Show how many sources and rules you have.",
    "release": "Build a shareable rule release with licence details.",
    "site": "Build a static website from a rule release.",
    "runs": "Review past updates and accept a failed one.",
    "quarantine": "Inspect lines that look like rules but do not parse.",
    "version": "Show the version, the database schema, Python, the main libraries and the engines.",
}

EPILOG = "Help for any command: suriharvest COMMAND --help."


def panel_for(name: str) -> str:
    return next((panel for panel, names in PANELS.items() if name in names), OTHER)


def command_order(name: str) -> tuple[int, int, str]:
    panel = panel_for(name)
    names = PANELS.get(panel, ())
    return list(PANELS).index(panel) if panel in PANELS else len(PANELS), names.index(name) if name in names else 0, name


def summary(name: str) -> str | None:
    text = SUMMARIES.get(name)
    if text and name in START_EXAMPLES:
        text = f"{text} Example: {START_EXAMPLES[name]}"
    return text


_VALUE_LIST = re.compile(r"^\S+ \| ")  # `keep | review | drop`: a list of values keeps its spelling


def sentence(text: str | None) -> str | None:
    """`bind address; anything but loopback needs --token-env` -> `Bind address; ... --token-env.`"""
    if not text:
        return text
    text = text.strip()
    if text[0].islower() and not _VALUE_LIST.match(text):
        text = text[0].upper() + text[1:]
    if not text.endswith((".", "!", "?", ":")):
        text += "."
    return text


def _prepare(command: Any) -> None:
    for param in getattr(command, "params", ()):
        if getattr(param, "help", None):
            param.help = sentence(param.help)
    if isinstance(command, TyperGroup):
        for child in command.commands.values():
            _prepare(child)


class HelpGroup(TyperGroup):
    """The root command: panels in the order of PANELS, sentence-style option help in every command."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        for name, command in self.commands.items():
            command.rich_help_panel = panel_for(name)
            if text := summary(name):
                command.short_help = text
        _prepare(self)

    def list_commands(self, ctx: Any) -> list[str]:
        return sorted(self.commands, key=command_order)
