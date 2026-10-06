"""Render a ScanResult as coloured text, JSON or SARIF 2.1.0."""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, List

from . import __version__
from .findings import RULES, Finding, Severity
from .scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",  # white on red
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_GREEN = "\033[1;32m"

_LABEL = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MEDIUM: "MED ", Severity.LOW: "LOW ", Severity.INFO: "INFO"}


def use_color(stream=None, force: bool = False, disable: bool = False) -> bool:
    if disable or os.environ.get("NO_COLOR"):
        return False
    if force or os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    try:
        return stream.isatty() and os.environ.get("TERM") != "dumb"
    except Exception:
        return False


def render_text(result: ScanResult, color: bool = True, min_severity: str = Severity.LOW, verbose: bool = False, width: int = 100) -> str:
    def c(code: str, s: str) -> str:
        return "%s%s%s" % (code, s, _RESET) if color else s

    lines: List[str] = []
    shown = [f for f in result.findings if Severity.rank(f.severity) >= Severity.rank(min_severity)]
    hidden = len(result.findings) - len(shown)
    lines.append(c(_BOLD, "trapscan %s" % __version__) + c(_DIM, "  %s" % result.target))
    lines.append(c(_DIM, "  %d files, %d rules, %.2fs" % (result.files_scanned, result.rules_run, result.duration_s)))
    lines.append("")

    if not shown:
        lines.append(c(_GREEN, "  No traps found") + c(_DIM, " at severity >= %s." % min_severity))
        if hidden:
            lines.append(c(_DIM, "  (%d lower-severity notes hidden; use --all to show them)" % hidden))
    else:
        current = None
        for f in shown:
            if f.severity != current:
                current = f.severity
                lines.append("")
            tag = c(_COLORS[f.severity], " %s " % _LABEL[f.severity])
            loc = f.path + (":%d" % f.line if f.line else "")
            lines.append("%s %s  %s" % (tag, c(_BOLD, f.rule), f.title))
            lines.append("       %s" % c(_DIM, loc) if loc else "")
            if f.snippet:
                snippet = f.snippet if len(f.snippet) <= width - 10 else f.snippet[: width - 13] + "..."
                lines.append("       %s" % c("\033[0;37m", "| " + snippet))
            if f.detail and (verbose or f.detail != _rule_desc(f.rule)):
                lines.append("       %s" % _wrap(f.detail, width - 7, "       "))
            if verbose:
                if f.detail == _rule_desc(f.rule):
                    lines.append("       %s" % _wrap(f.detail, width - 7, "       "))
                if f.fix:
                    lines.append("       %s %s" % (c(_GREEN, "fix:"), _wrap(f.fix, width - 12, "            ")))
        lines.append("")
        counts = result.count_by_severity()
        summary = ", ".join("%d %s" % (counts[s], s) for s in Severity.ALL if counts[s])
        lines.append(c(_BOLD, "  %d finding(s): " % len(result.findings)) + summary)
        if hidden:
            lines.append(c(_DIM, "  (%d below --min-severity hidden; use --all to show)" % hidden))
        if not verbose:
            lines.append(c(_DIM, "  Run with -v for explanations and fixes, --json for machine output."))
    if result.skipped_large:
        lines.append(c(_DIM, "  %d file(s) over the size limit were not content-scanned." % result.skipped_large))
    for n in result.notes:
        lines.append(c(_DIM, "  note: %s" % n))
    return "\n".join(l for l in lines if l is not None)


def _rule_desc(rule_id: str) -> str:
    for r in RULES:
        if r.id == rule_id:
            return r.description
    return ""


def _wrap(text: str, width: int, indent: str) -> str:
    import textwrap

    w = textwrap.wrap(text, width=max(30, width))
    return ("\n" + indent).join(w) if w else text


def render_json(result: ScanResult, pretty: bool = True) -> str:
    doc = {
        "tool": "trapscan",
        "version": __version__,
        "target": result.target,
        "files_scanned": result.files_scanned,
        "rules_run": result.rules_run,
        "duration_s": round(result.duration_s, 3),
        "summary": result.count_by_severity(),
        "max_severity": result.max_severity(),
        "findings": [f.to_dict() for f in result.findings],
        "notes": result.notes,
    }
    return json.dumps(doc, indent=2 if pretty else None, ensure_ascii=False)


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_SARIF_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "2.0", Severity.INFO: "0.5"}


def render_sarif(result: ScanResult) -> str:
    used: Dict[str, Finding] = {}
    for f in result.findings:
        used.setdefault(f.rule, f)
    rules_meta = []
    index: Dict[str, int] = {}
    for i, rid in enumerate(sorted(used)):
        meta = next((r for r in RULES if r.id == rid), None)
        index[rid] = i
        rules_meta.append(
            {
                "id": rid,
                "name": rid.replace("-", ""),
                "shortDescription": {"text": meta.title if meta else used[rid].title},
                "fullDescription": {"text": meta.description if meta else used[rid].detail},
                "help": {"text": meta.fix if meta else used[rid].fix, "markdown": "**Fix:** %s" % (meta.fix if meta else used[rid].fix)},
                "defaultConfiguration": {"level": _SARIF_LEVEL[meta.severity if meta else used[rid].severity]},
                "properties": {"security-severity": _SARIF_SCORE[meta.severity if meta else used[rid].severity], "tags": ["security", meta.category if meta else ""]},
            }
        )
    results = []
    for f in result.findings:
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path or ".", "uriBaseId": "%SRCROOT%"}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
            if f.snippet:
                loc["physicalLocation"]["region"]["snippet"] = {"text": f.snippet}
        results.append(
            {
                "ruleId": f.rule,
                "ruleIndex": index.get(f.rule, 0),
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": "%s: %s%s" % (f.title, f.detail, (" Fix: " + f.fix) if f.fix else "")},
                "locations": [loc],
                "properties": {"severity": f.severity},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "trapscan", "version": __version__, "informationUri": "https://github.com/kosys0224-spec/trapscan", "rules": rules_meta}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def render_rules_table(color: bool = False) -> str:
    from .scanner import _load_rules

    _load_rules()
    out = []
    by_cat: Dict[str, List] = {}
    for r in RULES:
        by_cat.setdefault(r.category, []).append(r)
    for cat in sorted(by_cat):
        out.append("%s (%d)" % (cat.upper(), len(by_cat[cat])))
        for r in sorted(by_cat[cat], key=lambda x: (-Severity.rank(x.severity), x.id)):
            out.append("  %-26s %-8s %s" % (r.id, r.severity, r.title))
        out.append("")
    out.append("%d rules total" % len(RULES))
    return "\n".join(out)
