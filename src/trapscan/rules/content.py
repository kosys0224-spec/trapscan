"""Content-level checks over every text file: hidden Unicode, download-and-run, decode-and-eval, exfil URLs, binaries."""
from __future__ import annotations

import os
import re
from typing import Iterator

from ..findings import Finding, Severity, rule
from ..util import inline_ignored, iter_lines, shorten, sniff_executable

CAT = "content"

CODE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".java",
    ".kt", ".kts", ".swift", ".rb", ".php", ".pl", ".pm", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",
    ".lua", ".dart", ".scala", ".groovy", ".gradle", ".ex", ".exs", ".erl", ".hs", ".ml", ".clj", ".r", ".jl", ".nim",
    ".zig", ".v", ".sv", ".vhd", ".vhdl", ".m", ".sql", ".vue", ".svelte", ".astro", ".mk", ".cmake", ".nix", ".tf", ".tcl",
}
DOC_EXT = {".md", ".mdx", ".rst", ".txt", ".adoc", ".org", ".tex", ".html", ".htm", ".csv", ".tsv", ".po", ".pot", ".srt", ".vtt", ".bib", ".json", ".cff", ".license", ".cfg"}
SKIP_CONTENT_EXT = {".lock", ".sum", ".map", ".svg", ".pdf", ".ipynb", ".snap", ".patch", ".diff", ".mo", ".min.js", ".min.css"}

_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\u180e]")
_TAGS = re.compile(r"[\U000E0000-\U000E007F]")
_NON_LATIN = re.compile("[\u2000-\U0010FFFF]")
_RTL_SCRIPT = re.compile(r"[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufeff]")

_PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b[^\n|;&]{0,200}\|\s*(sudo\s+(-\w+\s+)*)?"
    r"((ba|z|da|k)?sh|python[23]?|perl|ruby|node|php|iex|Invoke-Expression|powershell|pwsh|source)\b",
    re.I,
)
# (pattern, explanation, lowercase literals - the pattern is only tried when one of them occurs in the file)
_DECODE_EXEC = [
    (re.compile(r"\bbase64\s+(-d|--decode|-D)\b[^\n]{0,80}\|\s*(sudo\s+)?(ba|z|da)?sh\b|echo\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|\s*base64", re.I),
     "Base64 blob decoded and handed to a shell.", ('base64',)),
    (re.compile(r"\b(eval|exec|new\s+Function|Function)\s*\(\s*(atob|Buffer\.from|base64|b64decode|decodeURIComponent|unescape|String\.fromCharCode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads|pickle\.loads|lzma|gzip\.decompress|bz2\.decompress)", re.I),
     "eval/exec of decoded or constructed code.", ('eval', 'exec', 'function')),
    (re.compile(r"(\\x[0-9a-fA-F]{2}){24,}|(\\u00[0-9a-fA-F]{2}){24,}|(\\[0-7]{3}){24,}"),
     "Long escaped-byte string (obfuscated payload).", ('\\\\x', '\\\\u00', '\\\\0', '\\\\1', '\\\\2', '\\\\3')),
    (re.compile(r"String\.fromCharCode\s*\(\s*(\d{2,3}\s*,\s*){12,}|(chr\(\d+\)\s*\+\s*){6,}|(\[char\]\d+\s*\+\s*){6,}", re.I),
     "Code assembled from character codes.", ('fromcharcode', 'chr(', '[char]')),
    (re.compile(r"(powershell|pwsh)(\.exe)?\b[^\n]{0,120}(-enc(odedcommand)?\s+|-e\s+|-ec\s+)[A-Za-z0-9+/=]{16,}", re.I),
     "Encoded PowerShell command.", ('powershell', 'pwsh')),
    (re.compile(r"(powershell|pwsh)(\.exe)?\b[^\n]{0,120}(-w(indowstyle)?\s+hidden|-ExecutionPolicy\s+(Bypass|Unrestricted)|-ep\s+bypass)", re.I),
     "MEDIUM:Hidden-window or policy-bypass PowerShell (common in dev tooling, but worth a look).", ('powershell', 'pwsh')),
    (re.compile(r"(IEX|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\[Convert\]::FromBase64String)", re.I),
     "PowerShell download-and-execute.", ('iex', 'invoke-expression')),
    (re.compile(r"(?<![\w.])(LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP|BASH_ENV|PROMPT_COMMAND|GIT_SSH_COMMAND|GIT_CONFIG_GLOBAL|GIT_EXEC_PATH)[\"']?\]?\s*[:=]\s*[\"']?[^\s\"']|NODE_OPTIONS[\"']?\]?\s*[:=]\s*[\"']?--require", re.I),
     "MEDIUM:Environment variable that injects code into other programs.", ('ld_preload', 'dyld_insert', 'pythonstartup', 'bash_env', 'prompt_command', 'git_ssh_command', 'git_config_global', 'git_exec_path', 'node_options')),
    (re.compile(r"\b(xattr\s+-d\s+com\.apple\.quarantine|spctl\s+--master-disable|Set-MpPreference\s+-Disable|Add-MpPreference\s+-ExclusionPath|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)", re.I),
     "Disables an OS protection (quarantine, Gatekeeper, Defender, firewall).", ('xattr', 'spctl', 'mppreference', 'advfirewall')),
    (re.compile(r"\b(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|set\s+\+o\s+history|Clear-History)\b", re.I),
     "Wipes shell history.", ('histfile', 'histsize', 'history', 'clear-history')),
]

_EXFIL_HOST = re.compile(
    r"https?://(?:[\w.-]*\.)?(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
    r"webhook\.site|requestbin\.\w+|pipedream\.net|burpcollaborator\.net|interact\.sh|oast\.(fun|live|me|online|pro|site)|"
    r"canarytokens\.com|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|localhost\.run|"
    r"pastebin\.com/raw|paste\.ee|hastebin\.com|ghostbin|transfer\.sh|0x0\.st|file\.io|anonfiles\.com|mega\.nz|"
    r"bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|t\.ly|rb\.gy|shorturl\.at|duckdns\.org|no-ip\.(com|org)|ddns\.net|hopto\.org|"
    r"[\w-]+\.onion)\b",
    re.I,
)
_RAW_IP_PRE = re.compile(r"://\d")
_RAW_IP = re.compile(r"\b[a-z][a-z0-9+.-]*://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?", re.I)


def _private_ip(ip: str) -> bool:
    parts = [int(p) for p in ip.split(".") if p.isdigit()]
    if len(parts) != 4 or any(p > 255 for p in parts):
        return True
    a, b = parts[0], parts[1]
    return a in (0, 10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or (a == 169 and b == 254) or a >= 224


_TAG_RUN = re.compile(r"[\U000E0000-\U000E007F]+")


def _tag_run_not_flag(body: str):
    """First run of Unicode tag characters that is NOT a subdivision-flag emoji (black flag + tags + cancel tag)."""
    for m in _TAG_RUN.finditer(body):
        prev = body[m.start() - 1] if m.start() > 0 else ""
        if prev == "\U0001F3F4" and m.group(0).endswith("\U000E007F") and len(m.group(0)) <= 8:
            continue
        return m
    return None


def _benign_zero_width(body: str, m) -> bool:
    """ZWJ/ZWNJ are legitimate inside emoji sequences and in Arabic/Persian text."""
    ch = m.group(0)
    if ch not in ("\u200c", "\u200d"):
        return False
    prev = body[m.start() - 1] if m.start() > 0 else ""
    nxt = body[m.end()] if m.end() < len(body) else ""

    def emoji(c: str) -> bool:
        o = ord(c) if c else 0
        return o >= 0x1F000 or 0x2600 <= o <= 0x27BF or o in (0xFE0F, 0x200D, 0x20E3) or 0x1F3FB <= o <= 0x1F3FF

    if emoji(prev) or emoji(nxt):
        return True
    if ch == "\u200c" and _RTL_SCRIPT.search(body[max(0, m.start() - 40): m.end() + 40]):
        return True
    return False


def _line_hits(text: str, pattern):
    """Yield (lineno, line) for every line containing a match, searching the whole text once."""
    seen = set()
    for m in pattern.finditer(text):
        start = text.rfind("\n", 0, m.start()) + 1
        if start in seen:
            continue
        seen.add(start)
        end = text.find("\n", m.end())
        line = text[start: end if end >= 0 else len(text)]
        if inline_ignored(line):
            continue
        yield text.count("\n", 0, start) + 1, line


def _kind(rel: str) -> str:
    base = os.path.basename(rel).lower()
    ext = os.path.splitext(base)[1]
    for s in SKIP_CONTENT_EXT:
        if base.endswith(s):
            return "skip"
    if ext in DOC_EXT:
        return "doc"
    if ext in CODE_EXT or base in ("makefile", "justfile", "dockerfile", "rakefile", "gemfile", "procfile", "vagrantfile") or ext == "" or ext in (".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml"):
        return "code"
    return "other"


@rule(
    "UNICODE-HIDDEN", Severity.HIGH, "Invisible or direction-overriding Unicode in a source/config file", CAT,
    "Bidirectional override characters (Trojan Source) make code read differently than it compiles; zero-width "
    "characters and Unicode tag characters hide text from humans while tools and language models still see it.",
    "Open the file with `cat -A`/`less -U` or an editor that shows invisible characters, and remove them.",
)
def unicode_hidden(ctx) -> Iterator[Finding]:
    r = unicode_hidden.rule
    for fi in ctx.text_files():
        kind = _kind(fi.rel)
        if kind == "skip":
            continue
        text = ctx.text(fi)
        if not text or not _NON_LATIN.search(text):
            continue
        body = text[1:] if text.startswith("\ufeff") else text
        m = _tag_run_not_flag(body)
        if m:
            ln = body.count("\n", 0, m.start()) + 1
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), severity=Severity.CRITICAL,
                        detail="Unicode tag characters (U+E0000-E007F): invisible text that language models can read.")
        m = _BIDI.search(body)
        if m:
            ln = body.count("\n", 0, m.start()) + 1
            line = body.splitlines()[ln - 1]
            sev = Severity.HIGH if kind == "code" and not _RTL_SCRIPT.search(line) else Severity.LOW
            yield r.hit(fi.rel, ln, repr(line[:80]), severity=sev,
                        detail="Bidi control character%s." % (" in code (Trojan Source)" if sev == Severity.HIGH else " (file also contains RTL text or is documentation)"))
        zw = [m for m in _ZERO_WIDTH.finditer(body) if not _benign_zero_width(body, m)]
        if zw and (kind == "code" or len(zw) >= 3):
            m = zw[0]
            ln = body.count("\n", 0, m.start()) + 1
            line_txt = body.splitlines()[ln - 1].lstrip()
            testy = re.search(r"(test|spec|fixture|__snapshots__)", fi.rel, re.I) or line_txt.startswith(("*", "//", "#", "/*", "--", ";"))
            sev = (Severity.MEDIUM if testy else Severity.HIGH) if kind == "code" else (Severity.MEDIUM if len(zw) >= 10 else Severity.LOW)
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), severity=sev,
                        detail="%d zero-width character(s)%s." % (len(zw), " in code" if kind == "code" else " in documentation (often a copy-paste artifact)"))


@rule(
    "PIPE-TO-SHELL", Severity.MEDIUM, "Download piped directly into an interpreter", CAT,
    "`curl … | sh`, `wget … | python`, `iwr … | iex`: whatever the server returns runs immediately, unreviewed. "
    "Harmless in a README that you read first; dangerous in anything that runs automatically.",
    "Download to a file, read it, then run it.",
)
def pipe_to_shell(ctx) -> Iterator[Finding]:
    r = pipe_to_shell.rule
    for fi in ctx.text_files():
        kind = _kind(fi.rel)
        if kind == "skip":
            continue
        text = ctx.text(fi)
        if not text or "|" not in text:
            continue
        for ln, line in _line_hits(text, _PIPE_TO_SHELL):
            sev = Severity.LOW if kind == "doc" else Severity.MEDIUM
            yield r.hit(fi.rel, ln, line, severity=sev)


@rule(
    "OBFUSCATED-EXEC", Severity.HIGH, "Obfuscated or indirect code execution", CAT,
    "Code is decoded (base64/hex/char codes) and then evaluated, PowerShell is encoded or hidden, loader environment "
    "variables are set, or an OS protection is switched off. Legitimate projects rarely need to hide what they run.",
    "Decode the payload yourself and read it before running anything in this repository.",
)
def obfuscated_exec(ctx) -> Iterator[Finding]:
    r = obfuscated_exec.rule
    for fi in ctx.text_files():
        if _kind(fi.rel) == "skip":
            continue
        text = ctx.text(fi)
        if not text:
            continue
        lowered = text.lower()
        hits = 0
        seen_lines = set()
        for pat, raw_why, toks in _DECODE_EXEC:
            if not any(tok in lowered for tok in toks):
                continue
            soft = raw_why.startswith("MEDIUM:")
            why = raw_why[7:] if soft else raw_why
            for ln, line in _line_hits(text, pat):
                if ln in seen_lines:
                    continue
                seen_lines.add(ln)
                if soft:
                    sev = Severity.LOW if (_kind(fi.rel) == "doc" or re.search(r"(test|spec|fixture)", fi.rel, re.I)) else Severity.MEDIUM
                else:
                    sev = Severity.MEDIUM if _kind(fi.rel) == "doc" else Severity.HIGH
                yield r.hit(fi.rel, ln, line, detail=why, severity=sev)
                hits += 1
                if hits >= 8:
                    break
            if hits >= 8:
                break


@rule(
    "SUSPICIOUS-URL", Severity.MEDIUM, "URL to a webhook, tunnel, paste site, shortener or raw IP", CAT,
    "Chat webhooks and request-catchers are classic exfiltration endpoints; tunnels, paste sites, shorteners and raw "
    "IP addresses hide where code or data really goes.",
    "Resolve the URL (without visiting it) and ask why a code repository needs it.",
)
def suspicious_url(ctx) -> Iterator[Finding]:
    r = suspicious_url.rule
    for fi in ctx.text_files():
        if _kind(fi.rel) == "skip":
            continue
        text = ctx.text(fi)
        if not text or "://" not in text:
            continue
        hits = 0
        for ln, line in _line_hits(text, _EXFIL_HOST):
            m = _EXFIL_HOST.search(line)
            if m:
                host = m.group(1).lower()
                if re.match(r"(discord|api\.telegram|hooks\.slack|webhook\.site|requestbin|pipedream|burp|interact|oast|canary|.*\.onion)", host):
                    sev = Severity.MEDIUM if re.search(r"(test|spec|fixture)", fi.rel, re.I) else Severity.HIGH
                elif re.match(r"(bit\.ly|tinyurl|is\.gd|cutt\.ly|t\.ly|rb\.gy|shorturl)", host):
                    sev = Severity.MEDIUM if _kind(fi.rel) == "code" else Severity.LOW
                else:
                    sev = Severity.MEDIUM
                yield r.hit(fi.rel, ln, line, severity=sev, detail="Host: %s" % host)
                hits += 1
            if hits >= 6:
                break
        for ln, line in (_line_hits(text, _RAW_IP) if _RAW_IP_PRE.search(text) else ()):
            m = _RAW_IP.search(line)
            if m and not _private_ip(m.group(1)):
                yield r.hit(fi.rel, ln, line, severity=Severity.LOW if _kind(fi.rel) == "doc" else Severity.MEDIUM, detail="Raw public IP address %s." % m.group(1))
                hits += 1
            if hits >= 6:
                break


@rule(
    "BINARY-EXECUTABLE", Severity.MEDIUM, "Compiled executable committed to the repository", CAT,
    "A file has an ELF/PE/Mach-O header. Binaries cannot be reviewed like source; one with a misleading extension "
    "(.png, .txt, .dat) is a strong signal of a hidden payload.",
    "Check whether the project really needs to ship binaries; verify checksums against an official release.",
)
def binary_executable(ctx) -> Iterator[Finding]:
    r = binary_executable.rule
    expected_ext = {".exe", ".dll", ".so", ".dylib", ".node", ".pyd", ".bin", ".elf", ".o", ".a", ".lib", ".sys", ".ko", ".out", ".wasm", ".com", ".efi", ""}
    for fi in ctx.files:
        if fi.is_dir or fi.is_symlink or fi.size < 64 or fi.rel.startswith(".git/"):
            continue
        head = ctx.head(fi, 1024)
        kind = sniff_executable(head)
        if not kind:
            continue
        ext = os.path.splitext(fi.rel)[1].lower()
        misleading = ext not in expected_ext and not re.search(r"\.so\.\d", fi.rel)
        yield r.hit(fi.rel, None, "%s, %d bytes" % (kind, fi.size),
                    severity=Severity.HIGH if misleading else Severity.MEDIUM,
                    detail="%s with a non-executable extension '%s'." % (kind, ext) if misleading else "%s committed to source control." % kind)
    for fi in ctx.files:
        if not fi.is_dir and fi.rel.endswith(".pyc") and "__pycache__" not in fi.rel:
            yield r.hit(fi.rel, None, "compiled Python bytecode", severity=Severity.LOW, detail="Stray .pyc outside __pycache__ can shadow a .py module.")


@rule(
    "FILENAME-CONFUSABLE", Severity.MEDIUM, "File or directory name uses look-alike Unicode characters", CAT,
    "A name mixes Latin letters with Cyrillic/Greek look-alikes (e.g. '\u0430' U+0430 for 'a') or contains control/"
    "zero-width characters. It can impersonate a trusted file name (README.md, package.json, .gitignore).",
    "Rename or delete the file; check what the real file with that name contains.",
)
def filename_confusable(ctx) -> Iterator[Finding]:
    r = filename_confusable.rule
    confusable = re.compile(r"[\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u04bb\u0455\u0501\u051b\u051d\u03bf\u03bd\u0391\u0392\u0395\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425]")
    seen = set()
    for path in [f.rel for f in ctx.files] + list(ctx.dirs):
        for comp in path.split("/"):
            if comp in seen:
                continue
            if any(ord(c) < 32 for c in comp) or _ZERO_WIDTH.search(comp) or _BIDI.search(comp) or _TAGS.search(comp):
                seen.add(comp)
                yield r.hit(path, None, repr(comp), severity=Severity.HIGH, detail="Control or invisible character in file name.")
                break
            if confusable.search(comp) and re.search(r"[A-Za-z]", comp):
                seen.add(comp)
                yield r.hit(path, None, repr(comp), detail="Mixed Latin and Cyrillic/Greek letters.")
                break
            if "\u2024" in comp or "\uff0e" in comp or (comp.count(".") >= 2 and re.search(r"\.(txt|pdf|png|jpg|md|doc[x]?)\.(exe|scr|bat|cmd|ps1|js|vbs|hta|lnk)$", comp, re.I)):
                seen.add(comp)
                yield r.hit(path, None, repr(comp), severity=Severity.HIGH, detail="Double extension or fake dot: looks like a document, is executable.")
                break
