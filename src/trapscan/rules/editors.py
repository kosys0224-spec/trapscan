"""Things that execute when you *open* a folder in an editor or IDE."""
from __future__ import annotations

import re
from typing import Iterator

from ..findings import Finding, Severity, rule
from ..util import dict_get, find_line, flatten_command, load_jsonc, shorten

CAT = "editor"

# VS Code settings keys that point at a binary the editor will launch.
_VSCODE_EXEC_KEY = re.compile(
    r"(executablePath|\.path$|Path$|\.runtime$|nodePath|interpreter|tsdk|goroot|alternateTools|"
    r"allowAutomaticTasks|shell|defaultProfile|automationProfile|\.command$|\.binary$|serverPath|"
    r"\.toolPath$|\.cmd$|\.exe$|wrapper|launcher|\.java\.home$|javaHome|\.sdk$|\.home$|clangd\.path|"
    r"security\.workspace\.trust|\.env\.|terminal\.integrated\.profiles|terminal\.integrated\.env|"
    r"git\.path|python\.defaultInterpreterPath|python\.pythonPath|php\.validate\.executablePath|"
    r"eslint\.runtime|npm\.packageManager|terminal\.integrated\.shellArgs)",
    re.I,
)
_LOCAL_VALUE = re.compile(r"(\$\{workspaceFolder|\$\{workspaceRoot|^\.{1,2}/|^\./|^[A-Za-z0-9_.-]+/|\\\\|^\.)")


def _vscode_task_commands(tasks) -> Iterator[tuple]:
    if not isinstance(tasks, list):
        return
    for t in tasks:
        if not isinstance(t, dict):
            continue
        run_on = dict_get(t, "runOptions", "runOn")
        cmd = flatten_command(t.get("command")) + " " + flatten_command(t.get("args"))
        if not cmd.strip():
            cmd = flatten_command(t.get("script")) or t.get("label", "")
        yield run_on, cmd.strip(), t


@rule(
    "VSCODE-AUTOTASK", Severity.CRITICAL, "VS Code task runs automatically on folder open", CAT,
    "A task in .vscode/tasks.json has runOptions.runOn = folderOpen. In a trusted workspace VS Code "
    "runs it the moment the folder opens, with no further prompt.",
    "Read the command before opening. Set task.allowAutomaticTasks to off, or open in Restricted Mode.",
)
def vscode_autotask(ctx) -> Iterator[Finding]:
    r = vscode_autotask.rule
    for fi in list(ctx.glob("**/.vscode/tasks.json")) + list(ctx.glob("**/*.code-workspace")):
        text = ctx.text(fi)
        if not text:
            continue
        data = load_jsonc(text)
        if not isinstance(data, dict):
            continue
        tasks = data.get("tasks")
        if isinstance(tasks, dict):  # .code-workspace nests it
            tasks = tasks.get("tasks")
        for run_on, cmd, t in _vscode_task_commands(tasks):
            if run_on == "folderOpen":
                yield r.hit(fi.rel, find_line(text, "folderOpen"), cmd or shorten(str(t)),
                            detail="Runs on folder open: %s" % shorten(cmd or str(t)))


@rule(
    "VSCODE-SETTINGS-EXEC", Severity.HIGH, "Workspace settings point VS Code at a binary or shell", CAT,
    "`.vscode/settings.json` overrides a path/executable/terminal setting. Extensions launch the referenced "
    "program when the folder opens (classic trick: php.validate.executablePath, python.defaultInterpreterPath, "
    "git.path, terminal profiles).",
    "Inspect the referenced path. Values inside the workspace (./, ${workspaceFolder}) are the most suspicious.",
)
def vscode_settings_exec(ctx) -> Iterator[Finding]:
    r = vscode_settings_exec.rule
    targets = list(ctx.glob("**/.vscode/settings.json")) + list(ctx.glob("**/*.code-workspace"))
    for fi in targets:
        text = ctx.text(fi)
        if not text:
            continue
        data = load_jsonc(text)
        if not isinstance(data, dict):
            continue
        settings = data.get("settings") if fi.rel.endswith(".code-workspace") else data
        if not isinstance(settings, dict):
            continue
        for key, val in settings.items():
            if not _VSCODE_EXEC_KEY.search(key):
                continue
            if key == "task.allowAutomaticTasks":
                if str(val).lower() in ("on", "true"):
                    yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, val),
                                detail="Workspace re-enables automatic tasks.", severity=Severity.HIGH)
                continue
            if key.startswith("security.workspace.trust"):
                yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, val),
                            detail="Workspace tries to influence Workspace Trust behaviour.", severity=Severity.MEDIUM)
                continue
            sval = flatten_command(val) if not isinstance(val, (dict, list)) else shorten(str(val))
            local = bool(_LOCAL_VALUE.search(sval)) or "${workspaceFolder" in str(val)
            sev = Severity.HIGH if local else Severity.MEDIUM
            yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, shorten(sval, 100)),
                        detail="Setting %s changes which program VS Code executes%s." % (key, " (path inside the repo)" if local else ""),
                        severity=sev)


@rule(
    "VSCODE-LAUNCH-PRETASK", Severity.LOW, "Debug configuration runs a task before launch", CAT,
    "launch.json has preLaunchTask / postDebugTask or a runtimeExecutable inside the workspace. It runs when you press F5.",
    "Check the referenced task in tasks.json before debugging.",
)
def vscode_launch(ctx) -> Iterator[Finding]:
    r = vscode_launch.rule
    for fi in ctx.glob("**/.vscode/launch.json"):
        text = ctx.text(fi)
        data = load_jsonc(text) if text else None
        if not isinstance(data, dict):
            continue
        for cfg in data.get("configurations", []) or []:
            if not isinstance(cfg, dict):
                continue
            for key in ("preLaunchTask", "postDebugTask"):
                if cfg.get(key):
                    yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, cfg[key]))
            rt = cfg.get("runtimeExecutable")
            if isinstance(rt, str) and ("${workspaceFolder" in rt or rt.startswith(("./", "."))):
                yield r.hit(fi.rel, find_line(text, "runtimeExecutable"), "runtimeExecutable: %s" % rt,
                            severity=Severity.MEDIUM, detail="Debugging launches a binary that lives inside the repo.")


@rule(
    "VSCODE-EXTENSIONS", Severity.INFO, "Workspace recommends extensions", CAT,
    ".vscode/extensions.json lists recommended extensions; VS Code prompts to install them.",
    "Only install extensions from publishers you recognise.",
)
def vscode_extensions(ctx) -> Iterator[Finding]:
    r = vscode_extensions.rule
    for fi in ctx.glob("**/.vscode/extensions.json"):
        text = ctx.text(fi)
        data = load_jsonc(text) if text else None
        recs = data.get("recommendations") if isinstance(data, dict) else None
        if recs:
            yield r.hit(fi.rel, find_line(text, "recommendations"), ", ".join(str(x) for x in recs[:6]))


_DEVC_HOST = ("initializeCommand",)
_DEVC_CONTAINER = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")


@rule(
    "DEVCONTAINER-HOST-CMD", Severity.CRITICAL, "Dev container runs a command on your host machine", CAT,
    "devcontainer.json has `initializeCommand`, which runs on the *host* (not inside the container) when the "
    "folder is opened or reopened in a container.",
    "Read the command. Decline 'Reopen in Container' until you have.",
)
def devcontainer_host(ctx) -> Iterator[Finding]:
    r = devcontainer_host.rule
    for fi in _devcontainer_files(ctx):
        text = ctx.text(fi)
        data = load_jsonc(text) if text else None
        if not isinstance(data, dict):
            continue
        for key in _DEVC_HOST:
            if key in data:
                yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, shorten(flatten_command(data[key]))))


@rule(
    "DEVCONTAINER-LIFECYCLE", Severity.MEDIUM, "Dev container lifecycle command", CAT,
    "devcontainer.json runs commands inside the container on create/start/attach. They run with your mounted "
    "source, forwarded credentials and (often) Docker socket.",
    "Review the commands and the `mounts`/`runArgs` they get access to.",
)
def devcontainer_lifecycle(ctx) -> Iterator[Finding]:
    r = devcontainer_lifecycle.rule
    for fi in _devcontainer_files(ctx):
        text = ctx.text(fi)
        data = load_jsonc(text) if text else None
        if not isinstance(data, dict):
            continue
        for key in _DEVC_CONTAINER:
            if key in data:
                yield r.hit(fi.rel, find_line(text, key), "%s: %s" % (key, shorten(flatten_command(data[key]))))
        run_args = " ".join(str(x) for x in (data.get("runArgs") or []))
        mounts = " ".join(flatten_command(m) if not isinstance(m, str) else m for m in (data.get("mounts") or []))
        if "--privileged" in run_args or re.search(r"(^|[\s,=])/:/|docker\.sock|source=/(etc|root|home|var)\b", mounts + " " + run_args):
            yield r.hit(fi.rel, find_line(text, "runArgs") or find_line(text, "mounts"),
                        shorten(run_args + " " + mounts), severity=Severity.HIGH,
                        detail="Container is privileged or mounts sensitive host paths (root fs, docker socket, home).")


def _devcontainer_files(ctx):
    seen = set()
    for pat in ("**/.devcontainer/devcontainer.json", "**/.devcontainer.json", "**/.devcontainer/*/devcontainer.json"):
        for fi in ctx.glob(pat):
            if fi.rel not in seen:
                seen.add(fi.rel)
                yield fi


@rule(
    "JETBRAINS-RUNCONFIG", Severity.HIGH, "JetBrains run configuration executes a script or external tool", CAT,
    ".idea/ contains a run configuration of type Shell Script, or a 'Before launch' external tool, or a startup task. "
    "IntelliJ/PyCharm/… run these with a click (or on project open for startup tasks).",
    "Open .idea/*.xml in a text editor first; delete run configurations you did not write.",
)
def jetbrains_runconfig(ctx) -> Iterator[Finding]:
    r = jetbrains_runconfig.rule
    pats = ("**/.idea/runConfigurations/*.xml", "**/.idea/workspace.xml", "**/.run/*.xml", "**/.idea/*.xml")
    seen = set()
    for pat in pats:
        for fi in ctx.glob(pat):
            if fi.rel in seen:
                continue
            seen.add(fi.rel)
            text = ctx.text(fi)
            if not text:
                continue
            checks = (
                ("ShConfigurationType", Severity.HIGH, "Shell-script run configuration"),
                ("SCRIPT_TEXT", Severity.HIGH, "Inline shell script in run configuration"),
                ("ToolBeforeRunTask", Severity.HIGH, "External tool runs before launch"),
                ("RunConfigurationTask", Severity.MEDIUM, "Another run configuration runs before launch"),
                ("StartupTasks", Severity.HIGH, "Startup task runs when the project opens"),
                ("GradleBeforeRunTask", Severity.MEDIUM, "Gradle task runs before launch"),
                ("DockerBeforeRunTask", Severity.MEDIUM, "Docker build/run before launch"),
                ("externalDependencies", Severity.INFO, "Project asks to install plugins"),
            )
            for needle, sev, what in checks:
                if needle in text:
                    ln = find_line(text, needle)
                    snippet = text.splitlines()[ln - 1] if ln else needle
                    yield r.hit(fi.rel, ln, snippet, detail=what + ".", severity=sev)
                    break


@rule(
    "VIM-EXRC", Severity.HIGH, "Project-local Vim/Neovim config", CAT,
    "A .exrc/.vimrc/.nvimrc/.nvim.lua/.lazy.lua file in the repo is sourced automatically when Vim/Neovim is "
    "started in this directory with 'exrc' enabled (Neovim asks to trust it once).",
    "Read the file before answering the trust prompt. Prefer `:help exrc` secure mode.",
)
def vim_exrc(ctx) -> Iterator[Finding]:
    r = vim_exrc.rule
    names = (".exrc", ".vimrc", ".nvimrc", ".nvim.lua", ".lvimrc", ".vimrc.lua", ".lazy.lua", ".neoconf.json",
             ".vimrc.local", ".gvimrc", ".exrc.lua")
    for fi in ctx.by_name(*names):
        txt = ctx.text(fi) or ""
        hot = re.search(r"(:!|system\(|jobstart|termopen|os\.execute|io\.popen|vim\.fn\.system|silent!?\s*!|\bexe(cute)?\b)", txt)
        yield r.hit(fi.rel, 1, (txt.strip().splitlines() or [""])[0],
                    detail=("Contains a shell/exec call." if hot else "Editor config inside the repository."),
                    severity=Severity.HIGH if hot else Severity.LOW)


@rule(
    "EMACS-DIR-LOCALS", Severity.HIGH, "Emacs .dir-locals.el", CAT,
    ".dir-locals.el is evaluated when a file in this tree is opened. `eval` forms run arbitrary Lisp "
    "(Emacs asks unless the variables are marked safe).",
    "Read it. Treat any `eval` or `(shell-command …)` as code execution.",
)
def emacs_dir_locals(ctx) -> Iterator[Finding]:
    r = emacs_dir_locals.rule
    for fi in ctx.by_name(".dir-locals.el", ".dir-locals-2.el"):
        txt = ctx.text(fi) or ""
        hot = re.search(r"\((eval|shell-command|call-process|start-process|load|require)\b", txt)
        ln = None
        if hot:
            ln = txt.count("\n", 0, hot.start()) + 1
        yield r.hit(fi.rel, ln, txt.splitlines()[ln - 1] if ln else (txt.strip().splitlines() or [""])[0],
                    severity=Severity.HIGH if hot else Severity.LOW,
                    detail="Contains eval/shell forms." if hot else "Only sets variables (lower risk).")


@rule(
    "EDITOR-PROJECT-CONFIG", Severity.MEDIUM, "Other editor project file that can run commands", CAT,
    "Project files for Zed, Helix, Sublime Text, Visual Studio, Fleet or Gitpod/Codespaces define tasks, "
    "build systems or language-server binaries that the editor executes.",
    "Open the file in a plain text viewer and check every `command`, `shell_cmd`, `cmd` and binary path.",
)
def editor_project_config(ctx) -> Iterator[Finding]:
    r = editor_project_config.rule
    targets = {
        "**/.zed/tasks.json": r"\"command\"",
        "**/.zed/settings.json": r"(\"binary\"|\"path\"|\"command\")",
        "**/.helix/languages.toml": r"^\s*command\s*=",
        "**/*.sublime-project": r"(shell_cmd|\"cmd\")",
        "**/*.sublime-workspace": r"(shell_cmd|\"cmd\")",
        "**/.vs/tasks.vs.json": r"\"command\"",
        "**/.vs/launch.vs.json": r"(\"exe\"|\"program\")",
        "**/CMakeSettings.json": r"(cmakeExecutable|buildCommandArgs)",
        "**/.fleet/run.json": r"\"program\"",
        "**/.gitpod.yml": r"^\s*(init|command|before)\s*:",
        "**/.replit": r"^\s*(run|onBoot|entrypoint)\s*=",
        "**/.kate-project": r"(build|cmd)",
        "**/.projectile": r"\S",
        "**/.nova/Tasks/*.json": r"\"command\"",
        "**/.vscode/*.code-snippets": r"\\\\u200|\\\\u202",
    }
    for pat, needle in targets.items():
        for fi in ctx.glob(pat):
            text = ctx.text(fi)
            if text is None:
                continue
            m = re.search(needle, text, re.M)
            if not m:
                continue
            ln = text.count("\n", 0, m.start()) + 1
            sev = Severity.INFO if pat.endswith((".gitpod.yml", ".replit", ".projectile")) else Severity.MEDIUM
            yield r.hit(fi.rel, ln, text.splitlines()[ln - 1], severity=sev)
