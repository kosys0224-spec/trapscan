"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .findings import Severity
from .report import render_json, render_rules_table, render_sarif, render_text, use_color
from .scanner import DEFAULT_MAX_FILE_SIZE, ScanOptions, scan_path

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trapscan",
        description="Scan a repository for things that execute the moment you open it: editor auto-tasks, "
        "devcontainer host commands, git config traps, install hooks, AI-agent hooks and prompt injection, "
        "hidden Unicode, download-and-run one-liners.",
        epilog="Exit code 0 = nothing at or above --fail-on, 1 = findings, 2 = error. "
        "Examples:\n  trapscan ./some-repo\n  trapscan clone https://github.com/org/repo\n  trapscan repo.zip --json\n"
        "  trapscan . --fail-on medium --sarif > results.sarif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", default=None, help="directory, .zip or .tar(.gz) to scan (default: current directory). Use 'clone' to clone first.")
    p.add_argument("clone_args", nargs="*", help=argparse.SUPPRESS)
    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="machine-readable JSON output")
    out.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 output (GitHub code scanning)")
    out.add_argument("-v", "--verbose", action="store_true", help="show explanation and fix for every finding")
    out.add_argument("-q", "--quiet", action="store_true", help="only print the summary line")
    out.add_argument("--all", action="store_true", help="show info-level findings too (same as --min-severity info)")
    out.add_argument("--min-severity", default=Severity.LOW, metavar="LEVEL", help="lowest severity to display (critical|high|medium|low|info; default low)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colours (also honours NO_COLOR)")
    out.add_argument("--color", action="store_true", help="force ANSI colours")
    sel = p.add_argument_group("selection")
    sel.add_argument("--fail-on", default=Severity.HIGH, metavar="LEVEL", help="exit 1 if any finding is at or above this severity (default high; 'never' to always exit 0)")
    sel.add_argument("--ignore", action="append", default=[], metavar="RULE", help="rule id to skip (repeatable, comma-separated ok)")
    sel.add_argument("--only", action="append", default=[], metavar="RULE", help="run only these rule ids (repeatable)")
    sel.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="path glob to skip (repeatable), e.g. --exclude 'docs/*'")
    sel.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE, metavar="BYTES", help="skip content rules for files larger than this (default 2 MiB)")
    misc = p.add_argument_group("other")
    misc.add_argument("--list-rules", action="store_true", help="print every rule and exit")
    misc.add_argument("--depth", type=int, default=None, help="(clone) shallow clone depth")
    misc.add_argument("--keep", action="store_true", help="(clone) keep the clone even if findings are found (default: keep, but warn)")
    misc.add_argument("--version", action="version", version="trapscan %s" % __version__)
    return p


def _split_rules(values: List[str]) -> set:
    out = set()
    for v in values:
        for part in v.split(","):
            if part.strip():
                out.add(part.strip().upper())
    return out


def _git_clone(url: str, dest: Optional[str], depth: Optional[int]) -> Path:
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git is not installed or not on PATH")
    if dest is None:
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        dest = name or "repo"
    if Path(dest).exists():
        raise RuntimeError("destination already exists: %s" % dest)
    cmd = [git, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=", "-c", "protocol.file.allow=never",
           "-c", "protocol.ext.allow=never", "clone", "--no-recurse-submodules"]
    if depth:
        cmd += ["--depth", str(depth)]
    cmd += ["--", url, dest]
    print("trapscan: cloning %s -> %s (hooks disabled, submodules not fetched)" % (url, dest), file=sys.stderr)
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        raise RuntimeError("git clone failed with exit code %d" % proc.returncode)
    return Path(dest)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(render_rules_table())
        return EXIT_CLEAN

    try:
        min_sev = Severity.INFO if args.all else Severity.parse(args.min_severity)
        fail_on = None if str(args.fail_on).lower() in ("never", "none", "off") else Severity.parse(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))
        return EXIT_ERROR  # pragma: no cover

    target = args.target or "."
    cloned_to: Optional[Path] = None
    try:
        if target == "clone":
            if not args.clone_args:
                parser.error("clone needs a repository URL: trapscan clone <url> [dir]")
            url = args.clone_args[0]
            dest = args.clone_args[1] if len(args.clone_args) > 1 else None
            cloned_to = _git_clone(url, dest, args.depth)
            target = str(cloned_to)
        elif args.clone_args:
            parser.error("unexpected extra arguments: %s" % " ".join(args.clone_args))

        options = ScanOptions(
            ignore_rules=_split_rules(args.ignore),
            exclude_globs=list(args.exclude),
            max_file_size=args.max_file_size,
        )
        rules = None
        if args.only:
            from .findings import RULES
            from .scanner import _load_rules

            _load_rules()
            wanted = _split_rules(args.only)
            rules = [r for r in RULES if r.id in wanted]
            unknown = wanted - {r.id for r in rules}
            if unknown:
                parser.error("unknown rule id(s): %s" % ", ".join(sorted(unknown)))
        result = scan_path(target, options, rules)
    except (FileNotFoundError, RuntimeError, PermissionError, OSError) as exc:
        print("trapscan: error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("trapscan: interrupted", file=sys.stderr)
        return EXIT_ERROR

    if args.sarif:
        print(render_sarif(result))
    elif args.json:
        print(render_json(result))
    else:
        color = use_color(sys.stdout, force=args.color, disable=args.no_color)
        if args.quiet:
            counts = result.count_by_severity()
            summary = ", ".join("%d %s" % (counts[s], s) for s in Severity.ALL if counts[s]) or "no findings"
            print("trapscan: %s  (%d files, %s)" % (result.target, result.files_scanned, summary))
        else:
            width = shutil.get_terminal_size((100, 20)).columns
            print(render_text(result, color=color, min_severity=min_sev, verbose=args.verbose, width=min(width, 140)))
        if cloned_to is not None:
            worst = result.max_severity()
            if worst and Severity.rank(worst) >= Severity.rank(Severity.MEDIUM):
                print("\ntrapscan: clone kept at %s - read the findings above before opening it in an editor or agent." % cloned_to, file=sys.stderr)
            else:
                print("\ntrapscan: clone at %s looks clean." % cloned_to, file=sys.stderr)

    worst = result.max_severity()
    if fail_on and worst and Severity.rank(worst) >= Severity.rank(fail_on):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
