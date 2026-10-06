"""Small helpers: tolerant JSON, line lookup, binary sniffing, simple INI/TOML-ish parsing."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def strip_json_comments(text: str) -> str:
    """Remove // and /* */ comments from JSONC without touching string contents."""
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def load_jsonc(text: str) -> Optional[Any]:
    """Parse JSON, JSONC (comments) and JSON with trailing commas. Returns None on failure."""
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        cleaned = _TRAILING_COMMA.sub(r"\1", strip_json_comments(text))
        return json.loads(cleaned)
    except ValueError:
        return None


def find_line(text: str, needle: str, start: int = 0) -> Optional[int]:
    """1-based line number of the first occurrence of `needle` in text, or None."""
    idx = text.find(needle, start)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_text(text: str, lineno: int) -> str:
    lines = text.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def iter_lines(text: str) -> Iterator[Tuple[int, str]]:
    for i, line in enumerate(text.splitlines(), 1):
        yield i, line


def walk_json(obj: Any, path: str = "$") -> Iterator[Tuple[str, Any]]:
    """Yield (json_path, value) for every node."""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_json(v, "%s.%s" % (path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_json(v, "%s[%d]" % (path, i))


def json_strings(obj: Any) -> Iterator[str]:
    for _, v in walk_json(obj):
        if isinstance(v, str):
            yield v


def flatten_command(value: Any) -> str:
    """Render a command that may be a string, list, or {command,args} object as one string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(flatten_command(v) for v in value)
    if isinstance(value, dict):
        parts = []
        for key in ("command", "args", "windows", "linux", "osx"):
            if key in value:
                parts.append(flatten_command(value[key]))
        return " ".join(p for p in parts if p)
    return str(value)


_BINARY_MAGIC = (
    (b"\x7fELF", "ELF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O executable"),
    (b"\xfe\xed\xfa\xcf", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
)


def sniff_executable(head: bytes) -> Optional[str]:
    """Return a description if the bytes look like a native executable."""
    for magic, name in _BINARY_MAGIC:
        if head.startswith(magic):
            return name
    if head[:2] == b"MZ" and len(head) >= 0x40:
        pe_off = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < pe_off <= len(head) - 4 and head[pe_off : pe_off + 4] == b"PE\x00\x00":
            return "Windows PE executable"
        if 0 < pe_off < 4096:
            return "Windows MZ/PE executable"
    return None


def looks_binary(head: bytes) -> bool:
    if not head:
        return False
    if b"\x00" in head:
        return True
    # Heuristic: lots of non-text bytes
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b\f\x1b"
    nontext = sum(1 for b in head if b not in text_chars and b < 0x80)
    return nontext / max(1, len(head)) > 0.30


_INI_SECTION = re.compile(r'^\s*\[\s*([^\]"]+?)(?:\s+"([^"]*)")?\s*\]\s*$')
_INI_KV = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.*?)\s*$")


def parse_git_config(text: str) -> List[Tuple[str, str, int]]:
    """Parse git-config / INI text into (dotted.key, value, lineno). Subsection names are kept."""
    out: List[Tuple[str, str, int]] = []
    section = ""
    for lineno, raw in iter_lines(text):
        line = raw.split("#", 1)[0].split(";", 1)[0] if not raw.strip().startswith(("#", ";")) else ""
        if not line.strip():
            continue
        m = _INI_SECTION.match(line)
        if m:
            sec, sub = m.group(1).strip().lower(), m.group(2)
            section = "%s.%s" % (sec, sub) if sub is not None else sec
            continue
        m = _INI_KV.match(line)
        if m and section:
            out.append(("%s.%s" % (section, m.group(1).lower()), m.group(2).strip().strip('"'), lineno))
    return out


_TOML_TABLE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*$")
_TOML_KV = re.compile(r"""^\s*([A-Za-z0-9_.\-"']+)\s*=\s*(.*?)\s*$""")


def parse_toml_lines(text: str) -> List[Tuple[str, str, int]]:
    """Very small TOML line scanner: yields (table.key, raw_value, lineno). Good enough for config sniffing."""
    out: List[Tuple[str, str, int]] = []
    table = ""
    for lineno, raw in iter_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _TOML_TABLE.match(line)
        if m:
            table = m.group(1).strip().strip('"').lower()
            continue
        m = _TOML_KV.match(line)
        if m:
            key = m.group(1).strip().strip('"').strip("'").lower()
            full = "%s.%s" % (table, key) if table else key
            out.append((full, m.group(2), lineno))
    return out


def yaml_scalar_lines(text: str) -> List[Tuple[int, str, str, int]]:
    """Cheap YAML scan: yields (indent, key, value, lineno) for `key: value` lines (value may be empty)."""
    out: List[Tuple[int, str, str, int]] = []
    pat = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z0-9_.\-/\"']+)\s*:\s*(.*?)\s*$")
    for lineno, raw in iter_lines(text):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = pat.match(raw)
        if m:
            out.append((len(m.group(1)), m.group(2).strip('"').strip("'"), m.group(3), lineno))
    return out


def norm(path: str) -> str:
    return path.replace("\\", "/")


def shorten(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def dict_get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


_INLINE_IGNORE = re.compile(r"trapscan:\s*ignore", re.I)


def inline_ignored(line: str) -> bool:
    """True when a line carries a `trapscan:ignore` marker (like noqa)."""
    return bool(_INLINE_IGNORE.search(line))
