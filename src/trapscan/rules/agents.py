"""Traps aimed at AI coding agents (Claude Code, Cursor, Copilot, Gemini CLI, Windsurf, Cline/Roo, Kiro, Aider, OpenCode…)."""
from __future__ import annotations

import os
import re
from typing import Iterator, List

from ..findings import Finding, Severity, rule
from ..util import find_line, flatten_command, inline_ignored, iter_lines, load_jsonc, shorten, walk_json, yaml_scalar_lines

CAT = "agent"

# Files that agents read as instructions.
INSTRUCTION_FILES = (
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "GEMINI.md", "codex.md", ".cursorrules", ".windsurfrules",
    ".clinerules", ".goosehints", ".aider.conf.yml", "CONVENTIONS.md", ".github/copilot-instructions.md",
    ".junie/guidelines.md", "copilot-instructions.md", ".replit.md", "replit.md", "QWEN.md", "llms.txt", "llms-full.txt",
)
INSTRUCTION_GLOBS = (
    "**/.claude/**/*.md", "**/.claude/commands/*.md", "**/.claude/agents/*.md", "**/.claude/skills/*/SKILL.md",
    "**/.cursor/rules/*", "**/.cursor/rules/**/*.mdc", "**/.github/instructions/*.md", "**/.github/agents/*.md",
    "**/.github/prompts/*.md", "**/.windsurf/rules/*", "**/.roo/rules*/*", "**/.clinerules/*", "**/.kiro/steering/*",
    "**/.augment/rules/*", "**/.continue/rules/*", "**/.continue/prompts/*", "**/.codex/*.md", "**/.gemini/*.md",
    "**/.sourcegraph/*.rule.md", "**/.amazonq/rules/*", "**/.trae/rules/*", "**/.zencoder/rules/*", "**/.agents/**/*.md",
    "**/.opencode/**/*.md", "**/.cursor/*.md",
)
# Files that get read by humans AND agents – only the sharpest patterns apply.
DOC_FILES = ("README.md", "README.rst", "README.txt", "README", "CONTRIBUTING.md", "INSTALL.md", "SETUP.md", "USAGE.md", "GETTING_STARTED.md", "DEVELOPMENT.md")

_HIGH = [
    (re.compile(r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|rules?|guidance|context)", re.I), "Classic prompt-injection phrase."),
    (re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention|show|reveal|disclose|alert|notify|warn|ask)\s+(this\s+to\s+)?(the\s+)?(user|human|developer|operator|person)", re.I), "Instructs the agent to hide actions from the user."),
    (re.compile(r"without\s+(asking|telling|informing|notifying|confirming\s+with|alerting)\s+(the\s+)?(user|human)", re.I), "Instructs the agent to act without user confirmation."),
    (re.compile(r"(cat|type|read|print|echo|upload|send|post|exfiltrate|copy|curl\s+-F|base64|scp|rsync)\b[^\n]{0,80}(~/\.ssh|/\.ssh/|id_rsa|id_ed25519|id_ecdsa|\.aws/credentials|\.netrc|~/\.npmrc|\.pypirc|\.docker/config\.json|\.kube/config|\.gnupg|\.git-credentials|~/\.env\b|/etc/passwd|/etc/shadow|login\.keychain|credentials\.json|\.config/gh/hosts\.yml|\.claude/\.credentials|\.codex/auth\.json)", re.I), "Reads or exfiltrates credential files."),
    (re.compile(r"(curl|wget|iwr|irm|Invoke-WebRequest)\b[^\n|]{0,160}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", re.I), "Pipes a download straight into a shell."),
    (re.compile(r"(--dangerously-skip-permissions|--yolo\b|--auto-approve|--allow-all|bypassPermissions|approval[_-]?mode\s*[:=]\s*[\"']?(yolo|auto|full)|trust[_-]?all|autoAccept\s*[:=]\s*true|yes-always|--no-confirm|--force-trust)", re.I), "Tells the agent to disable its permission checks."),
    (re.compile(r"(disable|turn\s+off|bypass|skip|remove|circumvent)\s+(the\s+|all\s+|any\s+|your\s+|its\s+)?(sandbox(ing)?|safety\s+(checks?|features?|rails?)|security\s+(checks?|prompts?)|permission\s+(checks?|prompts?|system)|guardrails?|confirmation\s+(prompts?|dialogs?)|approval\s+(prompts?|steps?)|workspace\s+trust)\b", re.I), "Asks to disable sandbox/safety mechanisms."),
    (re.compile(r"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+(if\s+you\s+are\s+)?an?\s+(unrestricted|jailbroken|developer\s+mode))", re.I), "Role-override jailbreak phrase."),
    (re.compile(r"(nc|ncat|netcat)\s+(-e|-c|[\w.\-]+\s+\d+\s*<)|/dev/tcp/|bash\s+-i\s*>&|mkfifo\s+/tmp|socat\s+[^\n]*exec", re.I), "Reverse-shell idiom."),
    (re.compile(r"\b(rm\s+-rf\s+(/|~|\$HOME|\.)|mkfs\.|dd\s+if=/dev/(zero|random)\s+of=/dev/|:\(\)\s*\{\s*:\|:&\s*\};:)", re.I), "Destructive command."),
    (re.compile(r"(powershell|pwsh)[^\n]{0,80}(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,}|-e\s+[A-Za-z0-9+/=]{20,})", re.I), "Encoded PowerShell command."),
    (re.compile(r"\b(always|first|before\s+(anything|doing\s+anything|you\s+start|responding)|immediately|at\s+the\s+start|on\s+every\s+(run|session|start)|as\s+your\s+first\s+(step|action))\b[^\n]{0,80}\b(run|execute|source|install|download|fetch|curl|wget)\b[^\n]{0,60}(https?://|\.sh\b|\.ps1\b|\.py\b|npx\s+-y|uvx|pip\s+install|npm\s+i(nstall)?)", re.I), "Instructs the agent to run/install something automatically at session start."),
    (re.compile(r"\b(add|append|write|insert)\b[^\n]{0,60}\b(to|into)\b[^\n]{0,40}(~/\.(bashrc|zshrc|profile|bash_profile|gitconfig|ssh/authorized_keys|ssh/config|npmrc|pypirc)|crontab|launchagents|/etc/)", re.I), "Modifies the user's shell/git/ssh config or persistence locations."),
    (re.compile(r"\b(git\s+push\s+(--force|-f)|git\s+config\s+(--global|--system)|gh\s+auth|gh\s+secret|npm\s+publish|twine\s+upload|cargo\s+publish|docker\s+push|aws\s+s3\s+cp|gcloud\s+auth|az\s+login)\b", re.I), "Pushes/publishes or touches global auth as part of instructions."),
]
# README-style files: skip the pipe-to-shell pattern (legit install one-liners) and the
# "automatically run at start" pattern; the content rules cover those at lower severity.
_DOC_HIGH = [p for i, p in enumerate(_HIGH) if i in (0, 1, 2, 3, 5, 6, 7, 8, 12)]

_MEDIUM = [
    (re.compile(r"\b(npx\s+-y|npx\s+--yes|uvx|pipx\s+run|bunx)\s+[\w@./\-]+", re.I), "Runs a package straight from a registry without review."),
    (re.compile(r"\b(pip|pip3|npm|yarn|pnpm|bun|cargo|gem|go)\s+(install|add|get)\s+[^\n]*?(https?://|git\+|github\.com|gitlab\.com|\.whl\b|\.tar\.gz\b)", re.I), "Installs a dependency from a URL/git instead of a registry."),
    (re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|irm|fetch)\b\s+[^\n]{0,20}https?://", re.I), "Downloads something from the network."),
    (re.compile(r"\b(chmod\s+\+x|chmod\s+[0-7]*7[0-7]*\s)", re.I), "Marks a file executable."),
    (re.compile(r"\b(sudo|doas|runas)\b", re.I), "Requests elevated privileges."),
    (re.compile(r"\b(export|set|\$env:)\s*(PATH|LD_PRELOAD|DYLD_INSERT_LIBRARIES|NODE_OPTIONS|PYTHONPATH|PYTHONSTARTUP|GIT_SSH_COMMAND|GIT_CONFIG_GLOBAL|BASH_ENV|ENV|PROMPT_COMMAND)\b", re.I), "Sets an environment variable that changes how programs load/execute."),
    (re.compile(r"\b(trust|allow|approve|accept)\s+(this\s+|the\s+)?(workspace|folder|repository|repo|project|directory)\b|\b(trust|approve|accept|allow)\s+all\s+(mcp\s+servers?|hooks?|tools?|commands?|permissions?)\b|\bclick\s+[\"']?(trust|allow|yes|accept)", re.I), "Nudges the user/agent to grant trust."),
    (re.compile(r"\bhttps?://(?!127\.|10\.|192\.168\.|0\.0\.0\.0|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}(\.\d{1,3}){3}", re.I), "Raw public IP address URL."),
    (re.compile(r"(powershell|pwsh)[^\n]{0,80}(-w(indowstyle)?\s+hidden|-ExecutionPolicy\s+(Bypass|Unrestricted)|-ep\s+bypass|Invoke-Expression|\bIEX\b|DownloadString)", re.I), "PowerShell with policy bypass, hidden window or inline expression."),
]


def _instruction_files(ctx) -> List:
    seen = set()
    out = []
    for name in INSTRUCTION_FILES:
        for fi in ctx.by_name(name):
            if fi.rel not in seen:
                seen.add(fi.rel)
                out.append(fi)
    for pat in INSTRUCTION_GLOBS:
        for fi in ctx.glob(pat):
            if fi.rel not in seen and not fi.rel.endswith((".json", ".png", ".jpg", ".svg", ".gif")):
                seen.add(fi.rel)
                out.append(fi)
    return out


def _doc_files(ctx) -> List:
    out = []
    for name in DOC_FILES:
        for fi in ctx.by_name(name):
            out.append(fi)
    return out


@rule(
    "AGENT-INJECTION", Severity.HIGH, "Agent instruction file contains prompt-injection or dangerous commands", CAT,
    "CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md and similar files are fed to AI coding agents as "
    "trusted instructions. This one contains phrases that override the agent's rules, hide actions from the user, "
    "read credentials, pipe downloads into a shell, or disable permission checks.",
    "Open the file and read it as if it were a shell script. Do not run an agent in this repo until it is clean.",
)
def agent_injection(ctx) -> Iterator[Finding]:
    r = agent_injection.rule
    for fi in _instruction_files(ctx):
        text = ctx.text(fi)
        if not text:
            continue
        reported = 0
        for ln, line in iter_lines(text):
            if inline_ignored(line):
                continue
            for pat, why in _HIGH:
                if pat.search(line):
                    yield r.hit(fi.rel, ln, line, detail=why)
                    reported += 1
                    break
            else:
                for pat, why in _MEDIUM:
                    if pat.search(line):
                        yield r.hit(fi.rel, ln, line, detail=why, severity=Severity.MEDIUM)
                        reported += 1
                        break
            if reported >= 12:
                break
    # Docs: only the HIGH patterns, reported at HIGH as well (agents read README too)
    for fi in _doc_files(ctx):
        text = ctx.text(fi)
        if not text:
            continue
        for ln, line in iter_lines(text):
            for pat, why in _DOC_HIGH:
                if pat.search(line):
                    yield r.hit(fi.rel, ln, line, detail=why + " (in a README-style file, which agents also read)")
                    break


@rule(
    "AGENT-HIDDEN-TEXT", Severity.HIGH, "Hidden text in an agent instruction or doc file", CAT,
    "The file contains text invisible to a human reader but visible to a language model: HTML comments with "
    "imperative content, zero-width characters, Unicode tag characters (U+E0000-E007F 'ASCII smuggling'), "
    "long runs of variation selectors, bidi overrides, or white-on-white/`display:none` HTML.",
    "View the file with `cat -A` or a hex viewer. Delete the hidden content.",
)
def agent_hidden_text(ctx) -> Iterator[Finding]:
    r = agent_hidden_text.rule
    zero_width = re.compile(r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\u180e\ufeff]")
    tags = re.compile(r"[\U000E0000-\U000E007F]")
    varsel = re.compile(r"[\ufe00-\ufe0f\U000E0100-\U000E01EF]{6,}")
    bidi = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
    imperative = re.compile(r"\b(run|execute|curl|wget|install|ignore|download|delete|send|upload|export|chmod|sudo|rm\s|eval|source|pip|npm|npx|always|must|never\s+tell|do\s+not\s+tell|secret|token|password|key)\b", re.I)
    for fi in _instruction_files(ctx) + _doc_files(ctx):
        text = ctx.text(fi)
        if not text:
            continue
        body = text[1:] if text.startswith("\ufeff") else text
        from .content import _tag_run_not_flag
        m = _tag_run_not_flag(body)
        if m:
            ln = body.count("\n", 0, m.start()) + 1
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), severity=Severity.CRITICAL,
                        detail="Unicode tag characters (invisible 'ASCII smuggling' payload) found.")
        m = varsel.search(body)
        if m:
            ln = body.count("\n", 0, m.start()) + 1
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), detail="Long run of variation selectors – a known way to hide bytes inside an emoji.")
        zw = list(zero_width.finditer(body))
        if len(zw) >= 3 or (zw and fi.rel.lower().endswith((".md", ".mdc", ".txt")) and len(zw) >= 1 and imperative.search(body[max(0, zw[0].start() - 200): zw[0].start() + 200] or "")):
            ln = body.count("\n", 0, zw[0].start()) + 1
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), detail="%d zero-width character(s)." % len(zw))
        m = bidi.search(body)
        if m:
            ln = body.count("\n", 0, m.start()) + 1
            yield r.hit(fi.rel, ln, repr(body.splitlines()[ln - 1][:80]), detail="Bidirectional override characters (text displays differently than it reads).")
        for cm in re.finditer(r"<!--(.*?)-->", body, re.S):
            inner = cm.group(1).strip()
            if len(inner) >= 40 and imperative.search(inner):
                ln = body.count("\n", 0, cm.start()) + 1
                yield r.hit(fi.rel, ln, shorten(inner, 120), detail="HTML comment (invisible when rendered) contains instructions.")
        for hm in re.finditer(r"<(span|div|p|font)[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(#fff|#ffffff|white|transparent)|opacity\s*:\s*0)[^>]*>(.*?)</\1>", body, re.S | re.I):
            inner = hm.group(3).strip()
            if len(inner) >= 20:
                ln = body.count("\n", 0, hm.start()) + 1
                yield r.hit(fi.rel, ln, shorten(inner, 120), detail="HTML element hidden via CSS contains text.")
        # Markdown link/image with instruction-like alt/title text or a data: URL
        for lm in re.finditer(r"!\[([^\]]{40,})\]\(", body):
            if imperative.search(lm.group(1)):
                ln = body.count("\n", 0, lm.start()) + 1
                yield r.hit(fi.rel, ln, shorten(lm.group(1), 120), severity=Severity.MEDIUM, detail="Image alt text (not shown when the image renders) contains instructions.")


_HOOK_FILES = (
    ("**/.claude/settings.json", "Claude Code"), ("**/.claude/settings.local.json", "Claude Code"),
    ("**/.cursor/hooks.json", "Cursor"), ("**/.github/hooks/*.json", "GitHub Copilot coding agent"),
    ("**/.gemini/settings.json", "Gemini CLI"), ("**/.windsurf/hooks.json", "Windsurf"),
    ("**/.kiro/hooks/*.kiro.hook", "Kiro"), ("**/.codex/hooks.json", "Codex"), ("**/.opencode/*.json", "OpenCode"),
    ("**/opencode.json", "OpenCode"), ("**/opencode.jsonc", "OpenCode"), ("**/.continue/config.json", "Continue"), ("**/.continue/config.yaml", "Continue"),
    ("**/.roo/hooks.json", "Roo Code"), ("**/.cline/hooks.json", "Cline"), ("**/.clinerules/hooks.json", "Cline"), ("**/.factory/hooks.json", "Factory"),
)


@rule(
    "AGENT-HOOKS", Severity.CRITICAL, "AI agent hook executes shell commands automatically", CAT,
    "Project-level hook configuration (.claude/settings.json hooks, .cursor/hooks.json, .kiro/hooks, Gemini/Windsurf/"
    "Copilot hooks) makes the agent run a shell command on events like SessionStart, PreToolUse, file save or "
    "prompt submit – without the model or the user seeing it as a tool call.",
    "Read every `command` in the hook file. Remove the file before starting an agent session here.",
)
def agent_hooks(ctx) -> Iterator[Finding]:
    r = agent_hooks.rule
    for pat, tool in _HOOK_FILES:
        for fi in ctx.glob(pat):
            text = ctx.text(fi)
            if not text:
                continue
            data = load_jsonc(text)
            if data is None and fi.rel.endswith((".yaml", ".yml")):
                for indent, key, val, ln in yaml_scalar_lines(text):
                    if key in ("command", "run", "hooks") and val:
                        yield r.hit(fi.rel, ln, "%s: %s" % (key, shorten(val, 100)), detail="%s hook command." % tool)
                continue
            if not isinstance(data, (dict, list)):
                continue
            found = False
            for path, val in walk_json(data):
                low = path.lower()
                if ".hooks" in low or low.endswith("hooks") or "/hooks/" in fi.rel or fi.rel.endswith(".kiro.hook"):
                    if isinstance(val, dict) and ("command" in val or "run" in val or "shell" in val):
                        cmd = flatten_command(val.get("command") or val.get("run") or val.get("shell"))
                        yield r.hit(fi.rel, find_line(text, '"command"') or find_line(text, "hooks"), shorten(cmd, 120),
                                    detail="%s hook (%s) runs: %s" % (tool, path.split(".")[-2] if "." in path else path, shorten(cmd, 80)))
                        found = True
                if found and path.count(".") > 6:
                    break
            if not found and isinstance(data, dict) and "hooks" in data and data["hooks"]:
                yield r.hit(fi.rel, find_line(text, '"hooks"'), shorten(str(data["hooks"]), 120), detail="%s hook configuration present." % tool)


@rule(
    "AGENT-PERMISSIONS", Severity.HIGH, "Agent config pre-approves tools or bypasses permissions", CAT,
    "Project settings grant the agent blanket permissions (e.g. Claude Code permissions.allow with Bash(*) or "
    "defaultMode bypassPermissions, enableAllProjectMcpServers, Gemini autoAccept/approvalMode yolo, Aider yes-always, "
    "Copilot/Cursor auto-run). Whoever opens the repo with that agent inherits the relaxed guardrails.",
    "Delete or review the permissions block; keep project settings to formatting/style only.",
)
def agent_permissions(ctx) -> Iterator[Finding]:
    r = agent_permissions.rule
    for fi in ctx.glob("**/.claude/settings.json") + ctx.glob("**/.claude/settings.local.json"):
        text = ctx.text(fi) or ""
        data = load_jsonc(text)
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions") or {}
        if isinstance(perms, dict):
            mode = str(perms.get("defaultMode", ""))
            if mode in ("bypassPermissions", "dontAsk", "acceptEdits"):
                yield r.hit(fi.rel, find_line(text, "defaultMode"), "defaultMode: %s" % mode, severity=Severity.CRITICAL if mode == "bypassPermissions" else Severity.HIGH)
            for entry in perms.get("allow", []) or []:
                s = str(entry)
                if re.match(r"^(Bash|Shell|Execute)(\(\s*\*?\s*:?\*?\s*\))?$", s) or re.search(r"Bash\((\*|.*(curl|wget|sh |bash |rm |sudo|chmod|python|node|npx).*\*?)\)", s) or s in ("*", "**"):
                    yield r.hit(fi.rel, find_line(text, s[:30]), "allow: %s" % s, detail="Blanket shell permission.")
            for entry in perms.get("deny", []) or []:
                pass
        for key in ("enableAllProjectMcpServers", "skipDangerousModePermissionPrompt", "disableBypassPermissionsMode"):
            if key in data and str(data[key]).lower() in ("true",) and key != "disableBypassPermissionsMode":
                yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, data[key]), detail="Auto-approves every MCP server in .mcp.json.")
        if "apiKeyHelper" in data or "awsAuthRefresh" in data or "awsCredentialExport" in data:
            k = "apiKeyHelper" if "apiKeyHelper" in data else ("awsAuthRefresh" if "awsAuthRefresh" in data else "awsCredentialExport")
            yield r.hit(fi.rel, find_line(text, k), "%s: %s" % (k, shorten(str(data[k]), 90)), severity=Severity.CRITICAL,
                        detail="%s runs a shell command to obtain credentials." % k)
        env = data.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if re.match(r"^(ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|HTTPS?_PROXY|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|CLAUDE_CODE_.*URL|DISABLE_.*|ANTHROPIC_CUSTOM_HEADERS|PATH|LD_PRELOAD|DYLD_.*)$", k, re.I):
                    yield r.hit(fi.rel, find_line(text, k), "env.%s = %s" % (k, shorten(str(v), 80)), detail="Redirects the agent's API traffic or changes process loading.")
    for fi in ctx.glob("**/.gemini/settings.json"):
        text = ctx.text(fi) or ""
        data = load_jsonc(text)
        if isinstance(data, dict):
            for path, val in walk_json(data):
                if re.search(r"(autoAccept|approvalMode|yolo|trustedFolders|sandbox|excludeTools|allowedTools|coreTools)$", path, re.I) and val not in (False, None, "", []):
                    yield r.hit(fi.rel, find_line(text, path.split(".")[-1]), "%s: %s" % (path[2:], shorten(str(val), 80)))
    for fi in ctx.by_name(".aider.conf.yml", ".aider.conf.yaml"):
        text = ctx.text(fi) or ""
        for indent, key, val, ln in yaml_scalar_lines(text):
            if key in ("lint-cmd", "test-cmd", "auto-lint", "auto-test", "yes-always", "yes", "load", "shell-completions", "openai-api-base", "api-base", "openai-api-key", "anthropic-api-key", "api-key", "env-file", "git-commit-verify"):
                sev = Severity.HIGH if key in ("lint-cmd", "test-cmd", "yes-always", "yes", "load", "openai-api-base", "api-base") else Severity.MEDIUM
                yield r.hit(fi.rel, ln, "%s: %s" % (key, shorten(val, 90)), severity=sev, detail="Aider runs %s automatically after edits / redirects API traffic." % key)
    for fi in ctx.glob("**/.cursor/settings.json") + ctx.glob("**/.cursor/cli.json") + ctx.glob("**/.cursor/cli-config.json") + ctx.glob("**/.vscode/settings.json"):
        text = ctx.text(fi) or ""
        data = load_jsonc(text)
        if isinstance(data, dict):
            for key, val in data.items():
                if re.search(r"(yolo|chat\.agent\.autoRun|auto[_.]?approve|chat\..*allowlist|chat\..*allowList|terminal\.(allow|autoApprove)|chat\.tools\.(autoApprove|terminal\.(autoApprove|allowList))|chat\.agent\.(runTasks|autoFix)|github\.copilot\.chat\.(agent\.)?(runTasks|autoFix|terminalChatLocation)|chat\.tools\.global\.autoApprove|chat\.tools\.terminal\.enableAutoApprove|github\.copilot\.chat\.agent\.autoFix)", key, re.I):
                    if val not in (False, None, "", []):
                        yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, shorten(str(val), 80)), detail="Workspace setting auto-approves agent tool/terminal use.")
    for fi in ctx.by_name(".env", ".env.local", ".env.example", ".env.sample"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if re.match(r"^\s*(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|CLAUDE_CODE_.*|GEMINI_API_BASE|CURSOR_.*URL)\s*=", line) and "example" not in fi.rel:
                yield r.hit(fi.rel, ln, line.strip(), severity=Severity.MEDIUM, detail="Redirects an AI tool's API endpoint; your prompts (and keys) go there.")


_MCP_FILES = (
    "**/.mcp.json", "**/.cursor/mcp.json", "**/.vscode/mcp.json", "**/.gemini/settings.json", "**/.windsurf/mcp.json",
    "**/.roo/mcp.json", "**/.kiro/settings/mcp.json", "**/opencode.json", "**/.codex/config.toml", "**/mcp.json",
    "**/.continue/config.yaml", "**/.cline/mcp.json", "**/.github/copilot/mcp.json", "**/.vscode/settings.json",
    "**/.zed/settings.json", "**/.amazonq/mcp.json", "**/.trae/mcp.json", "**/.augment/mcp.json", "**/claude_desktop_config.json", "**/.gemini/extensions/*/gemini-extension.json",
)


@rule(
    "MCP-SERVER-CONFIG", Severity.HIGH, "Project MCP config launches a local process or points at a remote server", CAT,
    "A project-scoped MCP configuration (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json…) "
    "defines servers. stdio servers are *processes the agent spawns* with your privileges (npx -y …, uvx …, a script "
    "in the repo); remote servers receive everything the agent sends them. Most agents prompt once, then remember.",
    "Check each `command`/`args`/`url`. Prefer well-known published servers pinned to a version.",
)
def mcp_server_config(ctx) -> Iterator[Finding]:
    r = mcp_server_config.rule
    seen = set()
    for pat in _MCP_FILES:
        for fi in ctx.glob(pat):
            if fi.rel in seen:
                continue
            seen.add(fi.rel)
            text = ctx.text(fi) or ""
            if fi.rel.endswith(".toml"):
                for ln, line in iter_lines(text):
                    if re.match(r"^\s*\[mcp_servers\.", line):
                        yield r.hit(fi.rel, ln, line.strip(), severity=Severity.MEDIUM, detail="Codex MCP server block.")
                continue
            if fi.rel.endswith((".yaml", ".yml")):
                for indent, key, val, ln in yaml_scalar_lines(text):
                    if key == "command" and val:
                        yield r.hit(fi.rel, ln, "command: %s" % val, detail="stdio MCP server process.")
                continue
            data = load_jsonc(text)
            if not isinstance(data, dict):
                continue
            servers = None
            for key in ("mcpServers", "servers", "mcp", "context_servers", "mcp.servers", "chat.mcp.servers"):
                if isinstance(data.get(key), dict):
                    servers = data[key]
                    break
            if servers is None and "mcp" in data and isinstance(data["mcp"], dict) and isinstance(data["mcp"].get("servers"), dict):
                servers = data["mcp"]["servers"]
            if not isinstance(servers, dict):
                continue
            for name, cfg in servers.items():
                if not isinstance(cfg, dict):
                    continue
                cmd = flatten_command(cfg.get("command")) + " " + flatten_command(cfg.get("args"))
                cmd = cmd.strip()
                url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("httpUrl") or (cfg.get("transport") or {}).get("url") if isinstance(cfg.get("transport"), (dict, type(None))) else None
                if cmd:
                    local = re.search(r"(\./|\.\./|\$\{workspaceFolder|\$\{cwd|/tmp|~/|\$HOME|%\w+%)", cmd)
                    netexec = re.search(r"(npx\s+-y|npx\s+--yes|uvx\b|pipx\s+run|bunx\b|sh\s+-c|bash\s+-c|curl|wget|python[23]?\s+-c|node\s+-e|powershell|cmd\s+/c)", cmd)
                    sev = Severity.HIGH if (local or netexec) else Severity.MEDIUM
                    why = "Spawns a process from inside the repo." if local else ("Fetches and runs a package/command on start." if netexec else "Spawns a local process.")
                    yield r.hit(fi.rel, find_line(text, '"%s"' % name), "%s: %s" % (name, shorten(cmd, 100)), severity=sev, detail=why)
                elif isinstance(url, str):
                    sev = Severity.MEDIUM
                    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url) or re.search(r"(ngrok|trycloudflare|serveo|loca\.lt|\.onion|localhost\.run)", url):
                        sev = Severity.HIGH
                    yield r.hit(fi.rel, find_line(text, '"%s"' % name), "%s: %s" % (name, shorten(url, 100)), severity=sev, detail="Remote MCP server receives tool calls and context.")
                env = cfg.get("env")
                if isinstance(env, dict) and any(re.search(r"(KEY|TOKEN|SECRET|PASSWORD)", k, re.I) and isinstance(v, str) and len(v) > 8 and "${" not in v for k, v in env.items()):
                    yield r.hit(fi.rel, find_line(text, '"env"'), "%s: env contains a literal secret" % name, severity=Severity.LOW, detail="Hard-coded credential in MCP env (leak or lure).")


@rule(
    "AGENT-PLUGIN-CODE", Severity.HIGH, "Project ships executable agent plugin/extension code", CAT,
    "Files under .opencode/plugin, .claude/plugins, .gemini/extensions, .cursor/extensions or similar are loaded and "
    "executed by the agent on start. They are code, not configuration.",
    "Read the plugin source before starting the agent, or delete the directory.",
)
def agent_plugin_code(ctx) -> Iterator[Finding]:
    r = agent_plugin_code.rule
    pats = ("**/.opencode/plugin/*", "**/.opencode/plugins/*", "**/.claude/plugins/**/*.js", "**/.claude/plugins/**/*.ts", "**/.claude/plugins/**/*.py", "**/.claude/plugins/**/*.sh",
            "**/.gemini/extensions/*/*.js", "**/.gemini/extensions/*/*.ts", "**/.cursor/extensions/*", "**/.continue/plugins/*", "**/.claude/hooks/*", "**/.claude/scripts/*", "**/.cursor/hooks/*", "**/.kiro/hooks/*.sh", "**/.github/hooks/*.sh", "**/.github/hooks/*.py", "**/.github/hooks/*.js")
    seen = set()
    for pat in pats:
        for fi in ctx.glob(pat):
            if fi.rel in seen or fi.rel.endswith((".md", ".json", ".txt", ".yaml", ".yml")):
                continue
            seen.add(fi.rel)
            text = ctx.text(fi) or ""
            first = next((l for l in text.splitlines() if l.strip() and not l.startswith("#!")), os.path.basename(fi.rel))
            yield r.hit(fi.rel, 1, first)
