#!/usr/bin/env python3
"""Regenerate docs/rules.md from the rule registry. Run after adding or changing a rule."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trapscan.findings import RULES, Severity  # noqa: E402
from trapscan.scanner import _load_rules  # noqa: E402

CATEGORY_TITLES = {
    "editor": "Editor / IDE - runs when you open the folder",
    "git": "Git metadata - runs on git status / commit / checkout",
    "install": "Install & build - runs on npm install, pip install, cd, cargo build, commit, CI",
    "agent": "AI coding agents - hooks, permissions, MCP servers, prompt injection",
    "content": "File content - hidden Unicode, download-and-run, decode-and-eval, exfil URLs, binaries",
}


def main() -> int:
    _load_rules()
    out = ["# Rules", "", "trapscan ships %d rules. Severity is the *default*; individual findings may be raised or lowered "
           "(for example a harmless `prepare: husky` script is reported as low, a `curl | sh` in a README as low but in a "  # trapscan:ignore
           "Makefile as medium)." % len(RULES), "",
           "Disable a rule with `--ignore RULE-ID`, run a subset with `--only RULE-ID`, or silence one line with a "
           "`trapscan:ignore` comment.", ""]
    by_cat = {}
    for r in RULES:
        by_cat.setdefault(r.category, []).append(r)
    for cat in ("editor", "git", "install", "agent", "content"):
        rules = sorted(by_cat.get(cat, []), key=lambda x: (-Severity.rank(x.severity), x.id))
        out.append("## %s" % CATEGORY_TITLES.get(cat, cat))
        out.append("")
        out.append("| Rule | Default severity | What it finds |")
        out.append("|---|---|---|")
        for r in rules:
            out.append("| `%s` | %s | %s |" % (r.id, r.severity, r.title))
        out.append("")
        for r in rules:
            out.append("### `%s` - %s" % (r.id, r.title))
            out.append("")
            out.append("**Severity:** %s  " % r.severity)
            out.append("")
            out.append(r.description)
            out.append("")
            out.append("**Fix:** %s" % r.fix)
            out.append("")
    (ROOT / "docs" / "rules.md").write_text("\n".join(out), encoding="utf-8")
    print("wrote docs/rules.md (%d rules)" % len(RULES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
