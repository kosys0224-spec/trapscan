"""Walk a repository (or archive) and run every registered rule against it."""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from .findings import RULES, Finding, Rule, Severity
from .util import looks_binary, norm

DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024  # bytes read for content rules

# Directories whose *contents* are never interesting (but the directory itself may be).
SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "target", ".gradle", ".next", ".nuxt",
    ".terraform", ".svelte-kit", ".parcel-cache", ".turbo", "vendor", "Pods",
}
# Inside .git we only look at a few things.
GIT_INTERNAL_KEEP = {"config", "hooks", "info"}


@dataclass
class ScanOptions:
    ignore_rules: Set[str] = field(default_factory=set)
    exclude_globs: List[str] = field(default_factory=list)
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    follow_symlinks: bool = False


@dataclass
class FileInfo:
    rel: str          # posix-style relative path
    abs: Path
    size: int
    is_symlink: bool
    is_dir: bool = False


class Context:
    """Everything a rule needs: the file list, cached text reads, and lookup helpers."""

    def __init__(self, root: Path, options: Optional[ScanOptions] = None, display_root: Optional[str] = None):
        self.root = root.resolve()
        self.display_root = display_root or str(root)
        self.options = options or ScanOptions()
        self.files: List[FileInfo] = []
        self.dirs: Set[str] = set()
        self._by_rel: Dict[str, FileInfo] = {}
        self._text_cache: Dict[str, Optional[str]] = {}
        self._head_cache: Dict[str, bytes] = {}
        self._glob_cache: Dict[str, List[FileInfo]] = {}
        self._name_index: Dict[str, List[FileInfo]] = {}
        self.has_git_dir = False
        self.skipped_large = 0
        self._walk()

    # -- discovery -----------------------------------------------------------------
    def _excluded(self, rel: str) -> bool:
        for g in self.options.exclude_globs:
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g) or rel.startswith(g.rstrip("/") + "/"):
                return True
        return False

    def _walk(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=self.options.follow_symlinks):
            rel_dir = norm(os.path.relpath(dirpath, self.root))
            rel_dir = "" if rel_dir == "." else rel_dir
            parts = rel_dir.split("/") if rel_dir else []

            # Prune
            keep: List[str] = []
            for d in dirnames:
                rel = "%s/%s" % (rel_dir, d) if rel_dir else d
                if self._excluded(rel):
                    continue
                self.dirs.add(rel)
                full = Path(dirpath) / d
                if full.is_symlink():
                    # record the symlink as a file entry; do not descend
                    try:
                        size = 0
                    except OSError:
                        size = 0
                    fi = FileInfo(rel=rel, abs=full, size=size, is_symlink=True, is_dir=True)
                    self.files.append(fi)
                    self._by_rel[rel] = fi
                    continue
                if d == ".git" and not parts:
                    self.has_git_dir = True
                    keep.append(d)
                    continue
                if parts and parts[0] == ".git":
                    # inside .git: only descend into hooks/ and info/
                    if len(parts) == 1 and d in GIT_INTERNAL_KEEP:
                        keep.append(d)
                    continue
                if d in SKIP_DIRS or d == ".git" or d.endswith(".egg-info"):
                    continue
                keep.append(d)
            dirnames[:] = keep

            for f in filenames:
                rel = "%s/%s" % (rel_dir, f) if rel_dir else f
                if self._excluded(rel):
                    continue
                if parts and parts[0] == ".git":
                    if len(parts) == 1 and f not in GIT_INTERNAL_KEEP:
                        continue
                full = Path(dirpath) / f
                is_link = full.is_symlink()
                try:
                    size = 0 if is_link else full.stat().st_size
                except OSError:
                    size = 0
                fi = FileInfo(rel=rel, abs=full, size=size, is_symlink=is_link)
                self.files.append(fi)
                self._by_rel[rel] = fi
        self.files.sort(key=lambda x: x.rel)

    # -- lookups -------------------------------------------------------------------
    def exists(self, rel: str) -> bool:
        return rel in self._by_rel or rel in self.dirs

    def file(self, rel: str) -> Optional[FileInfo]:
        return self._by_rel.get(rel)

    def glob(self, pattern: str) -> List[FileInfo]:
        """fnmatch over posix relative paths. `**/x` also matches `x` at root. Results are cached."""
        cached = self._glob_cache.get(pattern)
        if cached is not None:
            return cached
        pats = [pattern]
        if pattern.startswith("**/"):
            pats.append(pattern[3:])
        regexes = [re.compile(fnmatch.translate(p)) for p in pats]
        # cheap prefilter: the last path component of the pattern, if literal
        tail = pattern.rsplit("/", 1)[-1]
        literal_tail = tail if not any(ch in tail for ch in "*?[") else None
        out = []
        for fi in self.files:
            if fi.is_dir:
                continue
            if literal_tail is not None and not fi.rel.endswith(literal_tail):
                continue
            if any(rx.match(fi.rel) for rx in regexes):
                out.append(fi)
        self._glob_cache[pattern] = out
        return out

    def by_name(self, *names: str, root_only: bool = False) -> List[FileInfo]:
        if not self._name_index:
            for fi in self.files:
                if not fi.is_dir:
                    self._name_index.setdefault(os.path.basename(fi.rel).lower(), []).append(fi)
        out = []
        for n in names:
            for fi in self._name_index.get(n.lower(), []):
                if root_only and "/" in fi.rel:
                    continue
                out.append(fi)
        out.sort(key=lambda x: x.rel)
        return out

    def head(self, fi: FileInfo, n: int = 4096) -> bytes:
        if fi.rel in self._head_cache:
            return self._head_cache[fi.rel]
        data = b""
        if not fi.is_symlink and not fi.is_dir:
            try:
                with open(fi.abs, "rb") as fh:
                    data = fh.read(n)
            except OSError:
                data = b""
        self._head_cache[fi.rel] = data
        return data

    def text(self, rel_or_fi) -> Optional[str]:
        """Decoded text of a file, or None if binary/unreadable/too large."""
        fi = rel_or_fi if isinstance(rel_or_fi, FileInfo) else self._by_rel.get(rel_or_fi)
        if fi is None or fi.is_dir:
            return None
        if fi.rel in self._text_cache:
            return self._text_cache[fi.rel]
        result: Optional[str] = None
        if fi.is_symlink:
            result = None
        elif fi.size > self.options.max_file_size:
            self.skipped_large += 1
            result = None
        else:
            head = self.head(fi)
            if looks_binary(head):
                result = None
            else:
                try:
                    raw = fi.abs.read_bytes()
                    for enc in ("utf-8", "utf-16"):
                        try:
                            result = raw.decode(enc)
                            break
                        except UnicodeDecodeError:
                            continue
                    if result is None:
                        result = raw.decode("latin-1")
                except OSError:
                    result = None
        self._text_cache[fi.rel] = result
        return result

    def text_files(self) -> Iterable[FileInfo]:
        for fi in self.files:
            if fi.is_dir or fi.is_symlink:
                continue
            if fi.size > self.options.max_file_size:
                continue
            yield fi


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    files_scanned: int
    rules_run: int
    duration_s: float
    skipped_large: int = 0
    notes: List[str] = field(default_factory=list)

    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: Severity.rank(f.severity)).severity

    def count_by_severity(self) -> Dict[str, int]:
        counts = {s: 0 for s in Severity.ALL}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


def _load_rules() -> None:
    # Import rule modules for their registration side effects.
    from .rules import editors, gitrules, build, agents, content  # noqa: F401


def run_rules(ctx: Context, rules: Optional[Sequence[Rule]] = None) -> List[Finding]:
    _load_rules()
    rules = list(rules) if rules is not None else list(RULES)
    findings: List[Finding] = []
    for r in rules:
        if r.id in ctx.options.ignore_rules:
            continue
        try:
            for f in r.func(ctx):
                findings.append(f)
        except Exception as exc:  # a broken rule must never kill the scan
            findings.append(
                Finding(
                    rule="TRAPSCAN-RULE-ERROR",
                    severity=Severity.INFO,
                    title="Rule crashed",
                    path="",
                    detail="Rule %s raised %s: %s" % (r.id, type(exc).__name__, exc),
                    fix="Please report this at the trapscan issue tracker.",
                    category="internal",
                )
            )
    # de-duplicate identical findings
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.rule, f.path, f.line, f.snippet, f.severity)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    unique.sort(key=lambda f: (-Severity.rank(f.severity), f.rule, f.path, f.line or 0))
    return unique


def _safe_extract_zip(zpath: Path, dest: Path, notes: List[str]) -> None:
    with zipfile.ZipFile(zpath) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.startswith(("/", "\\")) or ".." in Path(name).parts or ":" in name.split("/")[0]:
                notes.append("archive member skipped (path traversal): %s" % name)
                continue
            # zip symlinks: external_attr high bits 0xA000
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                notes.append("archive member is a symlink (not extracted): %s" % name)
                continue
            zf.extract(info, dest)


def _safe_extract_tar(tpath: Path, dest: Path, notes: List[str]) -> None:
    with tarfile.open(tpath) as tf:
        members = []
        for m in tf.getmembers():
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                notes.append("archive member skipped (path traversal): %s" % m.name)
                continue
            if m.issym() or m.islnk():
                notes.append("archive member is a link (not extracted): %s -> %s" % (m.name, m.linkname))
                continue
            if m.isdev():
                continue
            members.append(m)
        tf.extractall(dest, members=members)


def _is_archive(p: Path) -> Optional[str]:
    n = p.name.lower()
    if n.endswith(".zip"):
        return "zip"
    if n.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
        return "tar"
    return None


def scan_path(target, options: Optional[ScanOptions] = None, rules: Optional[Sequence[Rule]] = None) -> ScanResult:
    """Scan a directory or a .zip/.tar* archive. Returns a ScanResult."""
    target_path = Path(target)
    options = options or ScanOptions()
    notes: List[str] = []
    t0 = time.time()
    tmpdir: Optional[str] = None
    try:
        if target_path.is_file() and _is_archive(target_path):
            tmpdir = tempfile.mkdtemp(prefix="trapscan-")
            dest = Path(tmpdir)
            if _is_archive(target_path) == "zip":
                _safe_extract_zip(target_path, dest, notes)
            else:
                _safe_extract_tar(target_path, dest, notes)
            # If the archive has a single top-level folder, scan inside it.
            entries = [e for e in dest.iterdir()]
            root = entries[0] if len(entries) == 1 and entries[0].is_dir() else dest
            ctx = Context(root, options, display_root=str(target_path))
        elif target_path.is_dir():
            ctx = Context(target_path, options)
        else:
            raise FileNotFoundError("not a directory or supported archive: %s" % target)
        _load_rules()
        active = [r for r in (rules if rules is not None else RULES) if r.id not in options.ignore_rules]
        findings = run_rules(ctx, active)
        for f in findings:
            f.path = f.path or ""
        return ScanResult(
            target=str(target_path),
            findings=findings,
            files_scanned=sum(1 for f in ctx.files if not f.is_dir),
            rules_run=len(active),
            duration_s=time.time() - t0,
            skipped_large=ctx.skipped_large,
            notes=notes,
        )
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
