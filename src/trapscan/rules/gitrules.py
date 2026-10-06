"""Traps that live in Git metadata: .git/config, hooks, .gitattributes, .gitmodules, symlinks, odd names."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

from ..findings import Finding, Severity, rule
from ..util import iter_lines, parse_git_config

CAT = "git"

HOOK_NAMES = {
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
    "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
    "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change",
}

# key pattern -> (severity, why)
_GIT_CONFIG_TRAPS = [
    (re.compile(r"^core\.fsmonitor$"), Severity.CRITICAL, "core.fsmonitor runs a program on every `git status`/`git add` (the 'zipped repo' attack)."),
    (re.compile(r"^core\.hookspath$"), Severity.CRITICAL, "core.hooksPath points Git at hooks shipped inside the repository."),
    (re.compile(r"^core\.sshcommand$"), Severity.CRITICAL, "core.sshCommand replaces ssh for every fetch/push."),
    (re.compile(r"^core\.gitproxy$"), Severity.CRITICAL, "core.gitProxy runs a command for git:// transport."),
    (re.compile(r"^core\.(pager|editor)$"), Severity.CRITICAL, "core.pager/editor run a command on `git log`/`git commit`."),
    (re.compile(r"^core\.askpass$"), Severity.CRITICAL, "core.askPass runs a program to collect credentials."),
    (re.compile(r"^credential(\..*)?\.helper$"), Severity.CRITICAL, "credential.helper runs a program that receives your credentials."),
    (re.compile(r"^alias\."), Severity.CRITICAL, "Git alias can start with '!' and run any shell command."),
    (re.compile(r"^diff\..*\.(command|textconv)$"), Severity.CRITICAL, "diff driver executes a command on `git diff`."),
    (re.compile(r"^filter\..*\.(clean|smudge|process)$"), Severity.CRITICAL, "filter driver executes a command on checkout/commit."),
    (re.compile(r"^merge\..*\.driver$"), Severity.CRITICAL, "merge driver executes a command on merge."),
    (re.compile(r"^remote\..*\.(uploadpack|receivepack|vcs)$"), Severity.CRITICAL, "remote.*.uploadpack/receivepack run a program on fetch/push."),
    (re.compile(r"^(gpg\.program|gpg\..*\.program|ssh\.program|sequence\.editor|sendemail\.smtpserver|browser\..*\.cmd|web\.browser|difftool\..*\.cmd|mergetool\..*\.cmd|man\..*\.cmd|instaweb\..*|http\.proxy|http\.sslcainfo|http\.sslcert|http\.sslkey)$"), Severity.HIGH, "runs a program or redirects traffic/credentials."),
    (re.compile(r"^(include\.path|includeif\..*\.path)$"), Severity.HIGH, "include pulls in another config file (can hide the real trap)."),
    (re.compile(r"^url\..*\.insteadof$"), Severity.MEDIUM, "url.insteadOf rewrites remote URLs (redirects pushes/fetches)."),
    (re.compile(r"^(protocol\..*\.allow|protocol\.allow|safe\.directory|transfer\.fsckobjects|fetch\.fsckobjects|receive\.fsckobjects|uploadpack\.allow.*)$"), Severity.MEDIUM, "weakens Git safety settings."),
    (re.compile(r"^submodule\..*\.update$"), Severity.CRITICAL, "submodule.*.update can be '!command' and executes on `git submodule update`."),
]


def _git_config_files(ctx):
    seen = set()
    cands = []
    if ctx.has_git_dir and ctx.file(".git/config"):
        cands.append(ctx.file(".git/config"))
    # vendored/renamed git dirs, bare repos shipped inside the tree
    for fi in ctx.files:
        base = os.path.basename(fi.rel)
        if base == "config" and ("/.git/" in "/" + fi.rel or fi.rel.endswith((".git/config", "dot_git/config", "_git/config", "git/config"))):
            cands.append(fi)
        elif base in (".gitconfig", "gitconfig") or base.endswith(".gitconfig"):
            cands.append(fi)
    for fi in cands:
        if fi and fi.rel not in seen:
            seen.add(fi.rel)
            yield fi


@rule(
    "GIT-CONFIG-TRAP", Severity.CRITICAL, "Git config executes a command", CAT,
    "A .git/config (or a .gitconfig shipped in the repo) sets a key that makes Git run a program: fsmonitor, "
    "hooksPath, sshCommand, pager, editor, aliases starting with '!', diff/filter/merge drivers, credential helpers. "
    "`git clone` never produces these, so they come from an archive or a repo someone prepared by hand.",
    "Delete .git/config or open it and remove the key. Never run `git` inside an untrusted unzipped repo first.",
)
def git_config_trap(ctx) -> Iterator[Finding]:
    r = git_config_trap.rule
    for fi in _git_config_files(ctx):
        text = ctx.text(fi)
        if not text:
            continue
        for key, val, ln in parse_git_config(text):
            for pat, sev, why in _GIT_CONFIG_TRAPS:
                if pat.match(key):
                    if key.startswith("alias.") and not val.lstrip().startswith("!"):
                        sev2, why2 = Severity.LOW, "Git alias (does not start with '!', so no shell)."
                    elif key.startswith("submodule.") and not val.lstrip().startswith("!"):
                        sev2, why2 = Severity.LOW, "submodule update strategy (not a command)."
                    else:
                        sev2, why2 = sev, why
                    in_tree_dotfile = os.path.basename(fi.rel).lower() in (".gitconfig", "gitconfig") or fi.rel.endswith(".gitconfig")
                    if in_tree_dotfile and Severity.rank(sev2) > Severity.rank(Severity.MEDIUM):
                        sev2 = Severity.MEDIUM
                        why2 += " (This is a dotfile shipped in the tree; it only takes effect if you install it as your ~/.gitconfig.)"
                    yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail=why2, severity=sev2)
                    break


@rule(
    "GIT-HOOK-ACTIVE", Severity.CRITICAL, "Active Git hook shipped in .git/hooks", CAT,
    "The repository ships a .git directory with a real (non-.sample) hook. Git runs it on commit, checkout, merge, "
    "push, rebase… A fresh `git clone` never contains active hooks, so this came from an archive.",
    "Delete the hook or the whole .git/hooks directory before using Git in this checkout.",
)
def git_hook_active(ctx) -> Iterator[Finding]:
    r = git_hook_active.rule
    for fi in ctx.files:
        if fi.is_dir:
            continue
        parts = fi.rel.split("/")
        if len(parts) >= 3 and parts[-2] == "hooks" and parts[-3] in (".git", "dot_git", "_git"):
            name = parts[-1]
            if name.endswith(".sample"):
                continue
            if name in HOOK_NAMES or name.split(".")[0] in HOOK_NAMES:
                txt = ctx.text(fi) or ""
                first = next((l for l in txt.splitlines() if l.strip() and not l.startswith("#!")), "")
                if re.search(r"git[- ]lfs", txt) and len(txt) < 1200:
                    yield r.hit(fi.rel, 1, first, severity=Severity.LOW,
                                detail="Standard git-lfs hook. If you cloned this yourself, your own `git lfs install` put it here.")
                    continue
                yield r.hit(fi.rel, 1, first or "(binary hook)",
                            detail="If you ran `git clone` yourself, hooks come from your own template directory, not the author. "
                                   "If this checkout arrived as an archive or was prepared by someone else, treat it as hostile.")


@rule(
    "GIT-HOOKS-DIR", Severity.LOW, "Hook scripts shipped in the repo (inactive until configured)", CAT,
    "A .githooks/, .husky/, hooks/ or similar directory contains Git hook scripts. They only run after "
    "`git config core.hooksPath …`, `npm install` (husky), `pre-commit install`, or `lefthook install`.",
    "Fine to keep; just read them before running the project's install step.",
)
def git_hooks_dir(ctx) -> Iterator[Finding]:
    r = git_hooks_dir.rule
    reported = set()
    for fi in ctx.files:
        if fi.is_dir:
            continue
        parts = fi.rel.split("/")
        if len(parts) < 2:
            continue
        d = parts[-2].lower()
        if d in (".githooks", ".husky", "githooks", "git-hooks", "hooks", ".git-hooks", ".lefthook") and parts[0] != ".git":
            name = parts[-1]
            if name in HOOK_NAMES and "/".join(parts[:-1]) not in reported:
                reported.add("/".join(parts[:-1]))
                yield r.hit("/".join(parts[:-1]), None, name, detail="Hook directory: %s" % "/".join(parts[:-1]))


@rule(
    "GITATTRIBUTES-DRIVER", Severity.MEDIUM, ".gitattributes references a custom filter/diff/merge driver", CAT,
    "The attributes file assigns files to a filter=, diff= or merge= driver. Drivers are commands defined in git "
    "config; if that config also ships in the repo (GIT-CONFIG-TRAP) or you follow the README's `git config` "
    "instructions, Git executes them on checkout/diff/merge.",
    "Check which driver is referenced and whether the README asks you to configure it.",
)
def gitattributes_driver(ctx) -> Iterator[Finding]:
    r = gitattributes_driver.rule
    known_ok = {"lfs", "binary", "text", "-text", "-diff", "-merge", "union", "unset"}
    for fi in ctx.by_name(".gitattributes"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if line.strip().startswith("#"):
                continue
            for m in re.finditer(r"\b(filter|diff|merge)=([\w.\-]+)", line):
                if m.group(2) in known_ok:
                    continue
                sev = Severity.MEDIUM
                if m.group(2) in ("lfs",):
                    sev = Severity.INFO
                yield r.hit(fi.rel, ln, line, detail="%s driver '%s' is a user-configured command." % (m.group(1), m.group(2)), severity=sev)


@rule(
    "GITMODULES-SUSPICIOUS", Severity.HIGH, "Suspicious .gitmodules entry", CAT,
    ".gitmodules uses a relative/file:// URL, a raw IP, a path containing '..' or '.git', or an `update = !command` "
    "entry. These have been used for code execution and path traversal during `git clone --recursive` / `git submodule update`.",
    "Do not clone with --recursive. Inspect each submodule URL and path.",
)
def gitmodules_suspicious(ctx) -> Iterator[Finding]:
    r = gitmodules_suspicious.rule
    for fi in ctx.by_name(".gitmodules"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_git_config(text):
            k = key.rsplit(".", 1)[-1]
            v = val.strip()
            if k == "update" and v.startswith("!"):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.CRITICAL,
                            detail="submodule update = !command executes a shell command.")
            elif k == "url" and (v.startswith(("file://", "./", "../", "/", "ext::", "-")) or re.match(r"^[a-z]+://\d+\.\d+\.\d+\.\d+", v)):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail="Submodule URL is local/relative, an ext:: helper, or a raw IP.")
            elif k == "path" and (".." in v.split("/") or ".git" in v.lower().split("/") or v.startswith("/")):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail="Submodule path escapes the tree or targets .git/.")


@rule(
    "SYMLINK-ESCAPE", Severity.HIGH, "Symlink points outside the repository", CAT,
    "A symbolic link resolves to a location outside the checkout (or into .git/). Tools that follow links can read "
    "or overwrite files on your machine; some checkouts have used this to plant hooks.",
    "Delete the link or confirm the target is harmless.",
)
def symlink_escape(ctx) -> Iterator[Finding]:
    r = symlink_escape.rule
    root = ctx.root
    for fi in ctx.files:
        if not fi.is_symlink:
            continue
        try:
            target = os.readlink(fi.abs)
        except OSError:
            continue
        resolved = Path(os.path.normpath(os.path.join(os.path.dirname(fi.abs), target)))
        inside = str(resolved).startswith(str(root) + os.sep) or resolved == root
        into_git = inside and (".git" in Path(os.path.relpath(resolved, root)).parts)
        if not inside or into_git or os.path.isabs(target):
            yield r.hit(fi.rel, None, "-> %s" % target,
                        detail="Link target is outside the repo." if not inside else "Link target is inside .git/.")
        elif target.count("..") >= 2:
            yield r.hit(fi.rel, None, "-> %s" % target, severity=Severity.LOW, detail="Deeply relative link (stays inside the repo).")


@rule(
    "GIT-DIR-LOOKALIKE", Severity.HIGH, "Path component that mimics .git", CAT,
    "A directory is named like `.GIT`, `.Git`, `git~1` or `.git` with trailing dots/spaces. On case-insensitive or "
    "NTFS/HFS+ filesystems these can collide with the real .git directory and overwrite its config/hooks on checkout.",
    "Do not check this repository out on Windows/macOS; inspect the directory contents.",
)
def git_dir_lookalike(ctx) -> Iterator[Finding]:
    r = git_dir_lookalike.rule
    seen = set()
    for path in list(ctx.dirs) + [f.rel for f in ctx.files]:
        for comp in path.split("/"):
            c = comp.lower().rstrip(". ")
            if (c == ".git" and comp != ".git") or re.fullmatch(r"\.?git~\d", c) or re.fullmatch(r"\.g[i\u0456]t", comp.lower()) and comp != ".git":
                if comp not in seen:
                    seen.add(comp)
                    yield r.hit(path, None, comp)
                break
