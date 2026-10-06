"""Traps that fire on `npm install`, `pip install`, `cd`, `cargo build`, `git commit`, CI, or just viewing a folder."""
from __future__ import annotations

import os
import re
from typing import Iterator

from ..findings import Finding, Severity, rule
from ..util import find_line, iter_lines, load_jsonc, parse_toml_lines, shorten, yaml_scalar_lines

CAT = "install"

_NET_EXEC = re.compile(
    r"(curl|wget|fetch\s+http|Invoke-WebRequest|iwr\s|irm\s|certutil|bitsadmin|https?://|bash\s+-c|sh\s+-c|"
    r"node\s+-e|python[23]?\s+-c|powershell|pwsh|base64|eval\b|\$\(|`|\|\s*(ba|z)?sh\b|/dev/tcp|nc\s|chmod\s+\+x|"
    r"\.\./|/tmp/|\$HOME|~/|%USERPROFILE%|%APPDATA%|\.ssh|\.aws|\.npmrc|\.gitconfig|xattr|osascript|sudo\s)",
    re.I,
)
_HARMLESS_LIFECYCLE = re.compile(
    r"^(husky(\s+install)?|husky|node-gyp\s+rebuild|prebuild-install.*|tsc(\s.*)?|npm\s+run\s+build|"
    r"yarn\s+build|pnpm\s+build|patch-package|lerna\s+bootstrap|npm\s+run\s+(compile|prepare|build:\w+)|"
    r"lefthook\s+install|simple-git-hooks|is-ci\s*\|\|.*|nx\s.*|turbo\s.*|playwright\s+install.*|"
    r"electron-builder\s+install-app-deps|opencollective.*|node\s+scripts/postinstall\.js)$",
    re.I,
)
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare", "prepack", "postpack", "dependencies")


@rule(
    "NPM-LIFECYCLE", Severity.HIGH, "npm lifecycle script runs on install", CAT,
    "package.json defines preinstall/install/postinstall/prepare. `npm install` (also yarn/pnpm/bun) runs it "
    "automatically, with your user privileges, before you have read any code.",
    "Install with `npm install --ignore-scripts` first and read the script. For pnpm/yarn/bun, equivalent flags exist.",
)
def npm_lifecycle(ctx) -> Iterator[Finding]:
    r = npm_lifecycle.rule
    for fi in ctx.by_name("package.json"):
        text = ctx.text(fi)
        data = load_jsonc(text) if text else None
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for name in LIFECYCLE:
            cmd = scripts.get(name)
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            hot = _NET_EXEC.search(cmd)
            harmless = _HARMLESS_LIFECYCLE.match(cmd.strip())
            if harmless and not hot:
                sev, why = Severity.LOW, "Common, usually harmless lifecycle script."
            elif hot:
                sev, why = Severity.HIGH, "Downloads, decodes or executes something during install."
            else:
                sev, why = Severity.MEDIUM, "Runs a project script during install; read it."
            yield r.hit(fi.rel, find_line(text, '"%s"' % name), "%s: %s" % (name, shorten(cmd, 110)), detail=why, severity=sev)


@rule(
    "PKG-REGISTRY-OVERRIDE", Severity.HIGH, "Package manager config redirects downloads or disables protections", CAT,
    ".npmrc/.yarnrc.yml/bunfig.toml/pip requirements/uv/poetry/cargo/Gemfile config points the package manager at a "
    "non-default registry, index or mirror, adds --find-links, or turns off script/hash protections. Dependencies "
    "then come from a server the repository author controls.",
    "Compare the registry URL with the official one. Delete the override before installing.",
)
def pkg_registry_override(ctx) -> Iterator[Finding]:
    r = pkg_registry_override.rule
    official = re.compile(r"(registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|files\.pythonhosted\.org|"
                          r"crates\.io|index\.crates\.io|rubygems\.org|proxy\.golang\.org|npm\.pkg\.github\.com|"
                          r"pkg\.github\.com|registry\.npmmirror\.com|mirrors\.aliyun\.com|pypi\.tuna\.tsinghua\.edu\.cn|"
                          r"registry\.yarnpkg\.com|npm\.pkg\.github\.com|download\.pytorch\.org)")

    # npm / yarn classic
    for fi in ctx.by_name(".npmrc", ".yarnrc"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            s = line.strip()
            if not s or s.startswith(("#", ";")):
                continue
            key = s.split("=", 1)[0].strip().lower() if "=" in s else s.split(" ", 1)[0].strip().lower()
            val = s.split("=", 1)[1].strip() if "=" in s else (s.split(" ", 1)[1].strip() if " " in s else "")
            if key.endswith("registry") and not official.search(val):
                yield r.hit(fi.rel, ln, s, detail="Registry override to %s." % shorten(val, 60))
            elif key in ("ignore-scripts",) and val.lower() == "false":
                yield r.hit(fi.rel, ln, s, severity=Severity.MEDIUM, detail="Re-enables lifecycle scripts.")
            elif key in ("script-shell", "shell", "node-options", "unsafe-perm", "strict-ssl", "cafile", "ca", "cert", "key", "proxy", "https-proxy", "noproxy") and val:
                yield r.hit(fi.rel, ln, s, severity=Severity.MEDIUM if key not in ("script-shell", "node-options") else Severity.HIGH,
                            detail="%s changes how npm executes or where traffic goes." % key)
            elif key.startswith("//") and ("_authtoken" in key.lower() or "_auth" in key.lower()):
                yield r.hit(fi.rel, ln, s.split("=")[0] + "=…", severity=Severity.LOW, detail="Hard-coded auth token entry (leak or lure).")

    # yarn berry / bun
    for fi in ctx.by_name(".yarnrc.yml", ".yarnrc.yaml"):
        text = ctx.text(fi) or ""
        for indent, key, val, ln in yaml_scalar_lines(text):
            if key in ("npmRegistryServer", "npmPublishRegistry") and val and not official.search(val):
                yield r.hit(fi.rel, ln, "%s: %s" % (key, val))
            elif key == "enableScripts" and val.lower() == "true":
                yield r.hit(fi.rel, ln, "%s: %s" % (key, val), severity=Severity.LOW, detail="Explicitly enables lifecycle scripts.")
            elif key == "yarnPath":
                yield r.hit(fi.rel, ln, "%s: %s" % (key, val), severity=Severity.INFO,
                            detail="Yarn runs the bundled file %s instead of your global yarn (normal for Yarn Berry, but it is executable code in the repo)." % val)
            elif key in ("enableStrictSsl",) and val.lower() == "false":
                yield r.hit(fi.rel, ln, "%s: %s" % (key, val), severity=Severity.MEDIUM, detail="Disables TLS verification.")
    for fi in ctx.by_name("bunfig.toml"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if key.endswith("registry") and not official.search(val):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val))
            elif key.endswith("preload") or key == "preload":
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail="bunfig preload executes a script before every `bun` command in this directory.")

    # pip / uv / poetry / pdm
    for fi in ctx.files:
        base = os.path.basename(fi.rel).lower()
        if base.startswith("requirements") and base.endswith((".txt", ".in", ".pip")) or base in ("constraints.txt",):
            text = ctx.text(fi) or ""
            for ln, line in iter_lines(text):
                s = line.strip()
                if re.match(r"^(-i|--index-url|--extra-index-url|-f|--find-links|--trusted-host)\b", s) and not official.search(s):
                    yield r.hit(fi.rel, ln, s, detail="pip will fetch packages from %s." % shorten(s.split(None, 1)[-1], 60))
                elif re.search(r"^[\w.\-\[\]]+\s*@\s*https?://", s) and not official.search(s):
                    yield r.hit(fi.rel, ln, s, severity=Severity.MEDIUM, detail="Direct-URL dependency from a non-index host.")
    for fi in ctx.by_name("pip.conf", "pip.ini", "uv.toml", ".pdm.toml", "pdm.toml"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if re.search(r"(index-url|extra-index-url|find-links|trusted-host|index\s*=|url\s*=)", line, re.I) and not official.search(line):
                sev = Severity.HIGH if base_is(fi.rel, "uv.toml") else Severity.MEDIUM
                yield r.hit(fi.rel, ln, line.strip(), severity=sev,
                            detail="%s is read from the project directory by %s." % (os.path.basename(fi.rel), "uv" if base_is(fi.rel, "uv.toml") else "pip/pdm if configured"))
    for fi in ctx.by_name("pyproject.toml"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if key.startswith("tool.uv") and re.search(r"(index-url|extra-index-url|find-links|index\.url|\.url$)", key) and not official.search(val):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail="uv reads this from the project and will download packages from it.")
            elif key.startswith("tool.poetry.source") and key.endswith("url") and not official.search(val):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.MEDIUM)
            elif key.startswith("tool.pdm.source") and key.endswith("url") and not official.search(val):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.MEDIUM)

    # cargo / gems / go
    for fi in ctx.glob("**/.cargo/config.toml") + ctx.glob("**/.cargo/config"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if (key.startswith(("source.", "registries.", "registry.")) and re.search(r"(replace-with|registry|index|directory|local-registry)", key)) and not official.search(val):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.MEDIUM, detail="Cargo source replacement.")
    for fi in ctx.by_name("Gemfile"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            m = re.match(r"^\s*source\s+['\"]([^'\"]+)['\"]", line)
            if m and not official.search(m.group(1)):
                yield r.hit(fi.rel, ln, line.strip(), severity=Severity.MEDIUM, detail="Bundler source override.")
    for fi in ctx.by_name("go.env"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if re.match(r"^\s*(GOPROXY|GOFLAGS|GONOSUMDB|GONOSUMCHECK|GOINSECURE|GOPRIVATE)\s*=", line) and "proxy.golang.org" not in line:
                yield r.hit(fi.rel, ln, line.strip(), severity=Severity.MEDIUM)


def base_is(rel: str, name: str) -> bool:
    return os.path.basename(rel).lower() == name.lower()


@rule(
    "PY-INSTALL-HOOK", Severity.HIGH, "Python packaging file executes code on install", CAT,
    "setup.py calls os.system/subprocess/urllib/exec/eval/base64, pyproject.toml uses an in-tree build backend "
    "(backend-path) or an unknown build backend, or the repo ships sitecustomize.py/usercustomize.py/.pth files. "
    "These run on `pip install .`/`pip install -e .` – or, for .pth and sitecustomize, every time Python starts.",
    "Read setup.py and the build backend before installing. Delete stray .pth / sitecustomize files.",
)
def py_install_hook(ctx) -> Iterator[Finding]:
    r = py_install_hook.rule
    hot = re.compile(r"\b(os\.system|subprocess|popen|urllib|urlopen|requests\.|http\.client|socket\.|exec\(|eval\(|"
                     r"base64|compile\(|__import__|ctypes|shutil\.copy|open\([^)]*(\.ssh|\.aws|\.env|/etc/)|pathlib\.Path\.home|expanduser)", re.I)
    for fi in ctx.by_name("setup.py"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if line.strip().startswith("#"):
                continue
            if hot.search(line):
                yield r.hit(fi.rel, ln, line, detail="setup.py runs arbitrary code during install.")
                break
    known = ("setuptools", "hatchling", "flit_core", "flit", "poetry.core", "poetry", "pdm.backend", "pdm.pep517", "maturin",
             "scikit_build_core", "mesonpy", "whey", "enscons", "sip", "setuptools_scm", "py_build_cmake", "uv_build", "uv", "hatch")
    for fi in ctx.by_name("pyproject.toml"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if key == "build-system.backend-path":
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), detail="In-tree build backend: Python code in this repo runs on `pip install`.")
            elif key == "build-system.build-backend":
                v = val.strip().strip('"').strip("'")
                if not any(v == k or v.startswith(k + ".") or v.startswith(k + ":") for k in known):
                    yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.MEDIUM, detail="Unrecognised build backend '%s'." % v)
    for fi in ctx.files:
        base = os.path.basename(fi.rel)
        if base in ("sitecustomize.py", "usercustomize.py") or (base.endswith(".pth") and not fi.is_dir):
            yield r.hit(fi.rel, 1, (ctx.text(fi) or "").strip().splitlines()[:1][0] if (ctx.text(fi) or "").strip() else base,
                        detail="%s executes whenever the interpreter that picks it up starts." % base)
    for fi in ctx.by_name("conftest.py", root_only=True):
        text = ctx.text(fi) or ""
        if hot.search(text):
            ln = next((n for n, l in iter_lines(text) if hot.search(l) and not l.strip().startswith("#")), 1)
            yield r.hit(fi.rel, ln, text.splitlines()[ln - 1], severity=Severity.MEDIUM, detail="Root conftest.py runs on `pytest` and contains exec/network calls.")


@rule(
    "SHELL-AUTOLOAD", Severity.HIGH, "File is auto-sourced by the shell when you cd into the directory", CAT,
    ".envrc (direnv), .autoenv/.autoenv.zsh/.in (autoenv), .mise.toml/.rtx.toml hooks and tasks, or shell rc files "
    "committed to the repo. direnv and mise ask for a one-time `allow`/`trust`; autoenv runs immediately.",
    "Read it before `direnv allow` / `mise trust`. Never source untrusted rc files.",
)
def shell_autoload(ctx) -> Iterator[Finding]:
    r = shell_autoload.rule
    safe_envrc = re.compile(r"^\s*(#.*|export\s+\w+=.*|use\s+(nix|flake|node|python|ruby|asdf|rtx|mise)\b.*|layout\s+\w+.*|"
                            r"dotenv(_if_exists)?(\s.*)?|source_up(_if_exists)?(\s.*)?|source_env(_if_exists)?\s.*|PATH_add\s.*|"
                            r"watch_file\s.*|strict_env|unset\s+\w+|path_add\s.*|env_vars_required\s.*|has\s.*|log_status\s.*|)\s*$")
    for fi in ctx.by_name(".envrc"):
        text = ctx.text(fi) or ""
        hot_line = None
        for ln, line in iter_lines(text):
            if not safe_envrc.match(line) and line.strip():
                hot_line = (ln, line)
                break
        if hot_line:
            yield r.hit(fi.rel, hot_line[0], hot_line[1], detail="direnv executes this file as bash after `direnv allow`; it contains more than exports/layouts.")
        else:
            yield r.hit(fi.rel, 1, (text.strip().splitlines() or ["(empty)"])[0], severity=Severity.LOW, detail="direnv file with only exports/layout directives.")
    for fi in ctx.by_name(".autoenv", ".autoenv.zsh", ".autoenv_leave.zsh", ".in", ".out", ".env.sh"):
        if fi.rel.count("/") > 1:
            continue
        yield r.hit(fi.rel, 1, ((ctx.text(fi) or "").strip().splitlines() or [""])[0], detail="autoenv sources this when you cd here.")
    for fi in ctx.by_name(".mise.toml", "mise.toml", ".rtx.toml", ".mise.local.toml", "mise.local.toml", ".config/mise/config.toml"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if key.startswith(("hooks.", "tasks.")) or key in ("hooks", "tasks") or key.startswith("env._.source") or ".source" in key or key.startswith("env._.file"):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, shorten(val, 80)), detail="mise runs hooks on enter/leave and tasks on demand once the config is trusted.")
                break
    for fi in ctx.by_name(".bashrc", ".zshrc", ".profile", ".bash_profile", ".zshenv", ".zprofile", ".bash_login", ".kshrc", ".cshrc", ".tcshrc", ".config/fish/config.fish", "config.fish", ".xonshrc"):
        if fi.rel.count("/") == 0 or fi.rel.startswith(("dotfiles/", "home/", "etc/")):
            yield r.hit(fi.rel, 1, ((ctx.text(fi) or "").strip().splitlines() or [""])[0], severity=Severity.LOW,
                        detail="Shell rc file in the repo. Harmless unless copied or sourced (common in dotfiles repos).")
    for fi in ctx.by_name(".tool-versions"):
        text = ctx.text(fi) or ""
        if re.search(r"^\s*\w+\s+(path:|ref:|system)", text, re.M):
            yield r.hit(fi.rel, 1, text.strip().splitlines()[0], severity=Severity.MEDIUM, detail="asdf/mise tool version points at a path/ref instead of a release.")


@rule(
    "CARGO-CONFIG-EXEC", Severity.HIGH, "Cargo config overrides the compiler, linker, runner or aliases", CAT,
    ".cargo/config.toml sets rustc, rustc-wrapper, linker, runner, or an [alias]. `cargo build`/`cargo run`/`cargo test` "
    "then execute a program chosen by the repository, often a path inside the repo.",
    "Delete .cargo/config.toml or inspect every path in it before running cargo.",
)
def cargo_config_exec(ctx) -> Iterator[Finding]:
    r = cargo_config_exec.rule
    for fi in ctx.glob("**/.cargo/config.toml") + ctx.glob("**/.cargo/config"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            last = key.rsplit(".", 1)[-1]
            if last in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc", "linker", "runner", "ar", "credential-process", "credential-provider") or key.startswith("alias.") or last == "pre-link-args":
                sev = Severity.HIGH
                if key.startswith("alias."):
                    sev = Severity.HIGH if re.search(r"(\.\./|\./|/tmp|sh\b|bash|curl|wget|python)", val) else Severity.MEDIUM
                yield r.hit(fi.rel, ln, "%s = %s" % (key, shorten(val, 90)), severity=sev)
            elif key.startswith("env.") or key == "env":
                if re.search(r"(LD_PRELOAD|DYLD_|RUSTFLAGS|PATH|RUSTC|CC|CXX|LD_LIBRARY_PATH)", key.upper() + " " + val.upper()):
                    yield r.hit(fi.rel, ln, "%s = %s" % (key, shorten(val, 90)), severity=Severity.MEDIUM, detail="Cargo sets a loader/compiler environment variable for builds.")
    for fi in ctx.by_name("rust-toolchain.toml", "rust-toolchain"):
        text = ctx.text(fi) or ""
        for key, val, ln in parse_toml_lines(text):
            if key.endswith("path"):
                yield r.hit(fi.rel, ln, "%s = %s" % (key, val), severity=Severity.MEDIUM, detail="Toolchain points at a custom path – the compiler itself is replaced.")
    for fi in ctx.by_name("build.rs", root_only=False):
        text = ctx.text(fi) or ""
        net = re.search(r"\b(reqwest|ureq|TcpStream|std::net|curl|hyper::|attohttpc)\b", text)
        proc = re.search(r"\b(Command::new|std::process)\b", text)
        if net or proc:
            pat = r"(reqwest|ureq|TcpStream|std::net|curl|hyper::|attohttpc)" if net else r"(Command::new|std::process)"
            ln = next((n for n, l in iter_lines(text) if re.search(pat, l)), 1)
            yield r.hit(fi.rel, ln, text.splitlines()[ln - 1], severity=Severity.MEDIUM if net else Severity.LOW,
                        detail="build.rs opens network connections during `cargo build`." if net else "build.rs spawns a process during `cargo build` (common: git describe, pkg-config).")


@rule(
    "PRECOMMIT-LOCAL-HOOK", Severity.MEDIUM, "pre-commit config runs a local command", CAT,
    ".pre-commit-config.yaml defines `repo: local` hooks with language: system/script, or pulls hooks from an "
    "unusual URL. After `pre-commit install` they run on every commit.",
    "Read the `entry:` commands before `pre-commit install`.",
)
def precommit_local(ctx) -> Iterator[Finding]:
    r = precommit_local.rule
    for fi in ctx.by_name(".pre-commit-config.yaml", ".pre-commit-config.yml", "lefthook.yml", ".lefthook.yml", "lefthook.yaml", ".lefthook.yaml"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            s = line.strip()
            if re.match(r"^-?\s*entry\s*:", s) or re.match(r"^(run|runner)\s*:", s):
                cmd = s.split(":", 1)[1].strip()
                if _NET_EXEC.search(cmd) and not re.match(r"^(uv|poetry|npx|npm|pnpm|yarn|python[23]?|node|bash|sh|\./)[\w./ -]*$", cmd.strip()):
                    yield r.hit(fi.rel, ln, s, detail="Hook entry downloads/decodes/executes something unusual on commit.")
                elif re.search(r"(\./|\.\./|/tmp|python\s|bash\s|sh\s|node\s)", cmd):
                    yield r.hit(fi.rel, ln, s, severity=Severity.LOW, detail="Local hook runs a repo script on commit (common; read it once).")
            elif re.match(r"^-?\s*repo\s*:", s):
                url = s.split(":", 1)[1].strip()
                if url not in ("local", "meta") and not re.search(r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|pre-commit\.ci)", url):
                    yield r.hit(fi.rel, ln, s, detail="Hooks are fetched from an unusual host.")


@rule(
    "GHA-UNSAFE-WORKFLOW", Severity.HIGH, "GitHub Actions workflow is injectable or runs untrusted PR code", CAT,
    "A workflow uses pull_request_target/issue_comment/workflow_run together with a checkout of the PR head, or "
    "interpolates attacker-controlled context (issue title/body, PR title, head_ref, comment body) directly in `run:`. "
    "Relevant if you fork or maintain this repo: it leaks secrets to anyone who opens a PR.",
    "Use an environment variable instead of inline ${{ }} in run:, and never check out PR code under pull_request_target.",
)
def gha_unsafe(ctx) -> Iterator[Finding]:
    r = gha_unsafe.rule
    danger_ctx = re.compile(r"\$\{\{\s*github\.(event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|"
                            r"comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^.]+\.page_name|"
                            r"commits\.[^.]+\.(message|author\.(name|email))|head_commit\.(message|author\.(name|email)))|head_ref)\s*\}\}")
    for fi in ctx.glob("**/.github/workflows/*.yml") + ctx.glob("**/.github/workflows/*.yaml"):
        text = ctx.text(fi) or ""
        risky_trigger = re.search(r"^\s*(pull_request_target|issue_comment|workflow_run)\s*:", text, re.M) or re.search(r"^\s*on:\s*\[?[^\n]*(pull_request_target|issue_comment|workflow_run)", text, re.M)
        checkout_head = re.search(r"ref:\s*\$\{\{\s*github\.event\.(pull_request\.head\.(sha|ref)|workflow_run\.head_(sha|branch))", text)
        if risky_trigger and checkout_head:
            ln = text.count("\n", 0, checkout_head.start()) + 1
            yield r.hit(fi.rel, ln, text.splitlines()[ln - 1], detail="Privileged trigger checks out and (likely) runs code from the PR.")
        in_run = False
        for ln, line in iter_lines(text):
            if re.match(r"^\s*-?\s*run\s*:", line):
                in_run = True
            elif re.match(r"^\s*-?\s*[A-Za-z_\-]+\s*:", line) and not line.strip().startswith("-") and in_run and not line.startswith((" " * 10, "\t\t")):
                in_run = re.match(r"^\s*-?\s*run\s*:", line) is not None
            if in_run and danger_ctx.search(line):
                yield r.hit(fi.rel, ln, line, detail="Attacker-controlled text is pasted straight into a shell command (script injection).")
        seen_actions = set()
        for ln, line in iter_lines(text):
            m = re.search(r"uses:\s*([\w.\-]+)/([\w.\-]+)(/[\w./\-]+)?@(main|master|latest|dev|HEAD)\b", line)
            if m and m.group(1).lower() not in ("actions", "github") and m.group(0) not in seen_actions:
                seen_actions.add(m.group(0))
                yield r.hit(fi.rel, ln, line, severity=Severity.LOW, detail="Third-party action pinned to a moving branch, not a SHA/tag.")


@rule(
    "CONTAINER-HOST-ESCAPE", Severity.MEDIUM, "Compose/Docker config mounts the host or runs privileged", CAT,
    "docker-compose.yml (or Dockerfile/Vagrantfile) requests privileged mode, the Docker socket, the host root "
    "filesystem, host network/PID, or a home directory mount. `docker compose up` then has your machine.",
    "Review volumes/privileged/cap_add before starting the stack.",
)
def container_host_escape(ctx) -> Iterator[Finding]:
    r = container_host_escape.rule
    for fi in ctx.by_name("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "docker-compose.override.yml", "compose.override.yml"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            s = line.strip()
            if re.match(r"^privileged\s*:\s*true", s) or re.match(r"^(pid|network_mode|ipc)\s*:\s*[\"']?host", s) or re.search(r"(docker\.sock|^-\s*[\"']?/:/|^-\s*[\"']?/(etc|root|home|var/run|proc|sys|dev)[:/]|\$\{?HOME\}?:|~/?:)", s) or re.match(r"^-\s*(SYS_ADMIN|ALL|SYS_PTRACE|SYS_MODULE|NET_ADMIN)\b", s):
                yield r.hit(fi.rel, ln, s)
    for fi in ctx.by_name("Vagrantfile"):
        text = ctx.text(fi) or ""
        for ln, line in iter_lines(text):
            if re.search(r"(synced_folder\s+[\"']/[\"']|synced_folder\s+[\"']~|privileged\s*:\s*true|inline:\s*<<|trigger)", line):
                yield r.hit(fi.rel, ln, line, severity=Severity.LOW, detail="Vagrant triggers run on the host; shared root/home folders expose it.")
                break


_WIN_TRAP_EXT = {".lnk": "Windows shortcut (can launch any command when clicked; Explorer resolves icon paths on view)",
                 ".scf": "Shell Command File (leaks NTLM hash to a remote icon path just by viewing the folder)",
                 ".url": "Internet shortcut (IconFile= to a remote path leaks credentials; URL may be file://)",
                 ".library-ms": "Library file (remote icon/location, abused for NTLM relay and payload staging)",
                 ".settingcontent-ms": "Settings shortcut (runs DeepLink command on open)",
                 ".hta": "HTML Application (runs script with full trust on double-click)",
                 ".pif": "Program Information File (treated as executable)",
                 ".inf": "Setup information file (autorun.inf / installer)",
                 ".vbs": "VBScript", ".vbe": "Encoded VBScript", ".jse": "Encoded JScript", ".wsf": "Windows Script File", ".wsh": "Windows Script Host settings",
                 ".ps1": "PowerShell script", ".cmd": "Batch script", ".bat": "Batch script", ".reg": "Registry file", ".msc": "MMC snap-in", ".cpl": "Control panel applet", ".scr": "Screensaver executable", ".xll": "Excel add-in (code)", ".iso": "Disk image (bypasses Mark-of-the-Web)", ".img": "Disk image", ".vhd": "Disk image", ".vhdx": "Disk image", ".appinstaller": "App installer manifest", ".theme": "Windows theme (remote wallpaper path leaks NTLM)", ".diagcab": "Diagnostic cabinet (runs PowerShell)"}
_WIN_NAMES = {"desktop.ini": "desktop.ini can point IconResource at a remote share: Explorer leaks your NTLM hash when the folder is viewed.",
              "autorun.inf": "autorun.inf executes on media insertion / legacy autorun.",
              "thumbs.db": "Thumbnail cache (benign, but hides images; informational)."}
_MAC_EXT = {".command": "macOS Terminal script (runs on double-click)", ".tool": "macOS Terminal script", ".terminal": "Terminal settings file (can run a command on open)", ".webloc": "macOS web location file", ".app": "macOS application bundle", ".pkg": "macOS installer package", ".dmg": "macOS disk image", ".workflow": "Automator workflow", ".scpt": "AppleScript", ".applescript": "AppleScript"}


@rule(
    "OS-TRAP-FILE", Severity.MEDIUM, "File that executes or leaks credentials when viewed or double-clicked", CAT,
    "Windows and macOS treat some files specially: .lnk/.scf/.url/desktop.ini/.library-ms leak NTLM hashes or run "
    "commands as soon as Explorer renders the folder; .hta/.vbs/.ps1/.cmd/.command run on double-click; .iso/.img "
    "bypass Mark-of-the-Web. They rarely belong in a source repository.",
    "Do not open the folder in Explorer/Finder before deleting these files. Verify why they are in a code repo.",
)
def os_trap_file(ctx) -> Iterator[Finding]:
    r = os_trap_file.rule
    high_ext = {".lnk", ".scf", ".url", ".library-ms", ".settingcontent-ms", ".hta", ".pif", ".vbe", ".jse", ".wsf", ".theme", ".diagcab", ".xll", ".iso", ".img", ".vhd", ".vhdx", ".appinstaller", ".scr", ".cpl", ".msc"}
    low_ext = {".ps1", ".cmd", ".bat", ".vbs", ".reg", ".inf", ".command", ".tool", ".scpt", ".applescript", ".workflow", ".pkg", ".dmg", ".webloc", ".terminal"}
    for fi in ctx.files:
        if fi.is_dir:
            continue
        base = os.path.basename(fi.rel)
        ext = os.path.splitext(base)[1].lower()
        name = base.lower()
        if name in _WIN_NAMES:
            sev = Severity.HIGH if name in ("desktop.ini", "autorun.inf") else Severity.INFO
            text = ctx.text(fi) or ""
            if name == "desktop.ini" and not re.search(r"\\\\|https?:|IconResource|IconFile|ShellClassInfo", text, re.I):
                sev = Severity.LOW
            yield r.hit(fi.rel, None, shorten(text.strip().replace("\n", " "), 80) or base, detail=_WIN_NAMES[name], severity=sev)
        elif ext in high_ext:
            text = ctx.text(fi) or ""
            snip = shorten(text.strip().replace("\n", " "), 80) if text else "(binary)"
            yield r.hit(fi.rel, None, snip, detail=_WIN_TRAP_EXT.get(ext, _MAC_EXT.get(ext, "")), severity=Severity.HIGH)
        elif ext in low_ext and "/" not in fi.rel:
            # scripts in the repo root are common in legit projects; only mention them
            yield r.hit(fi.rel, None, base, detail=_WIN_TRAP_EXT.get(ext, _MAC_EXT.get(ext, "")) + " in the repo root.", severity=Severity.INFO)
        elif ext == ".app" or fi.rel.endswith(".app/Contents/Info.plist"):
            yield r.hit(fi.rel, None, base, detail=_MAC_EXT[".app"], severity=Severity.MEDIUM)
