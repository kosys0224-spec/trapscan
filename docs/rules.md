# Rules

trapscan ships 38 rules. Severity is the *default*; individual findings may be raised or lowered (for example a harmless `prepare: husky` script is reported as low, a `curl | sh` in a README as low but in a Makefile as medium).

Disable a rule with `--ignore RULE-ID`, run a subset with `--only RULE-ID`, or silence one line with a `trapscan:ignore` comment.

## Editor / IDE - runs when you open the folder

| Rule | Default severity | What it finds |
|---|---|---|
| `DEVCONTAINER-HOST-CMD` | critical | Dev container runs a command on your host machine |
| `VSCODE-AUTOTASK` | critical | VS Code task runs automatically on folder open |
| `EMACS-DIR-LOCALS` | high | Emacs .dir-locals.el |
| `JETBRAINS-RUNCONFIG` | high | JetBrains run configuration executes a script or external tool |
| `VIM-EXRC` | high | Project-local Vim/Neovim config |
| `VSCODE-SETTINGS-EXEC` | high | Workspace settings point VS Code at a binary or shell |
| `DEVCONTAINER-LIFECYCLE` | medium | Dev container lifecycle command |
| `EDITOR-PROJECT-CONFIG` | medium | Other editor project file that can run commands |
| `VSCODE-LAUNCH-PRETASK` | low | Debug configuration runs a task before launch |
| `VSCODE-EXTENSIONS` | info | Workspace recommends extensions |

### `DEVCONTAINER-HOST-CMD` - Dev container runs a command on your host machine

**Severity:** critical  

devcontainer.json has `initializeCommand`, which runs on the *host* (not inside the container) when the folder is opened or reopened in a container.

**Fix:** Read the command. Decline 'Reopen in Container' until you have.

### `VSCODE-AUTOTASK` - VS Code task runs automatically on folder open

**Severity:** critical  

A task in .vscode/tasks.json has runOptions.runOn = folderOpen. In a trusted workspace VS Code runs it the moment the folder opens, with no further prompt.

**Fix:** Read the command before opening. Set task.allowAutomaticTasks to off, or open in Restricted Mode.

### `EMACS-DIR-LOCALS` - Emacs .dir-locals.el

**Severity:** high  

.dir-locals.el is evaluated when a file in this tree is opened. `eval` forms run arbitrary Lisp (Emacs asks unless the variables are marked safe).

**Fix:** Read it. Treat any `eval` or `(shell-command …)` as code execution.

### `JETBRAINS-RUNCONFIG` - JetBrains run configuration executes a script or external tool

**Severity:** high  

.idea/ contains a run configuration of type Shell Script, or a 'Before launch' external tool, or a startup task. IntelliJ/PyCharm/… run these with a click (or on project open for startup tasks).

**Fix:** Open .idea/*.xml in a text editor first; delete run configurations you did not write.

### `VIM-EXRC` - Project-local Vim/Neovim config

**Severity:** high  

A .exrc/.vimrc/.nvimrc/.nvim.lua/.lazy.lua file in the repo is sourced automatically when Vim/Neovim is started in this directory with 'exrc' enabled (Neovim asks to trust it once).

**Fix:** Read the file before answering the trust prompt. Prefer `:help exrc` secure mode.

### `VSCODE-SETTINGS-EXEC` - Workspace settings point VS Code at a binary or shell

**Severity:** high  

`.vscode/settings.json` overrides a path/executable/terminal setting. Extensions launch the referenced program when the folder opens (classic trick: php.validate.executablePath, python.defaultInterpreterPath, git.path, terminal profiles).

**Fix:** Inspect the referenced path. Values inside the workspace (./, ${workspaceFolder}) are the most suspicious.

### `DEVCONTAINER-LIFECYCLE` - Dev container lifecycle command

**Severity:** medium  

devcontainer.json runs commands inside the container on create/start/attach. They run with your mounted source, forwarded credentials and (often) Docker socket.

**Fix:** Review the commands and the `mounts`/`runArgs` they get access to.

### `EDITOR-PROJECT-CONFIG` - Other editor project file that can run commands

**Severity:** medium  

Project files for Zed, Helix, Sublime Text, Visual Studio, Fleet or Gitpod/Codespaces define tasks, build systems or language-server binaries that the editor executes.

**Fix:** Open the file in a plain text viewer and check every `command`, `shell_cmd`, `cmd` and binary path.

### `VSCODE-LAUNCH-PRETASK` - Debug configuration runs a task before launch

**Severity:** low  

launch.json has preLaunchTask / postDebugTask or a runtimeExecutable inside the workspace. It runs when you press F5.

**Fix:** Check the referenced task in tasks.json before debugging.

### `VSCODE-EXTENSIONS` - Workspace recommends extensions

**Severity:** info  

.vscode/extensions.json lists recommended extensions; VS Code prompts to install them.

**Fix:** Only install extensions from publishers you recognise.

## Git metadata - runs on git status / commit / checkout

| Rule | Default severity | What it finds |
|---|---|---|
| `GIT-CONFIG-TRAP` | critical | Git config executes a command |
| `GIT-HOOK-ACTIVE` | critical | Active Git hook shipped in .git/hooks |
| `GIT-DIR-LOOKALIKE` | high | Path component that mimics .git |
| `GITMODULES-SUSPICIOUS` | high | Suspicious .gitmodules entry |
| `SYMLINK-ESCAPE` | high | Symlink points outside the repository |
| `GITATTRIBUTES-DRIVER` | medium | .gitattributes references a custom filter/diff/merge driver |
| `GIT-HOOKS-DIR` | low | Hook scripts shipped in the repo (inactive until configured) |

### `GIT-CONFIG-TRAP` - Git config executes a command

**Severity:** critical  

A .git/config (or a .gitconfig shipped in the repo) sets a key that makes Git run a program: fsmonitor, hooksPath, sshCommand, pager, editor, aliases starting with '!', diff/filter/merge drivers, credential helpers. `git clone` never produces these, so they come from an archive or a repo someone prepared by hand.

**Fix:** Delete .git/config or open it and remove the key. Never run `git` inside an untrusted unzipped repo first.

### `GIT-HOOK-ACTIVE` - Active Git hook shipped in .git/hooks

**Severity:** critical  

The repository ships a .git directory with a real (non-.sample) hook. Git runs it on commit, checkout, merge, push, rebase… A fresh `git clone` never contains active hooks, so this came from an archive.

**Fix:** Delete the hook or the whole .git/hooks directory before using Git in this checkout.

### `GIT-DIR-LOOKALIKE` - Path component that mimics .git

**Severity:** high  

A directory is named like `.GIT`, `.Git`, `git~1` or `.git` with trailing dots/spaces. On case-insensitive or NTFS/HFS+ filesystems these can collide with the real .git directory and overwrite its config/hooks on checkout.

**Fix:** Do not check this repository out on Windows/macOS; inspect the directory contents.

### `GITMODULES-SUSPICIOUS` - Suspicious .gitmodules entry

**Severity:** high  

.gitmodules uses a relative/file:// URL, a raw IP, a path containing '..' or '.git', or an `update = !command` entry. These have been used for code execution and path traversal during `git clone --recursive` / `git submodule update`.

**Fix:** Do not clone with --recursive. Inspect each submodule URL and path.

### `SYMLINK-ESCAPE` - Symlink points outside the repository

**Severity:** high  

A symbolic link resolves to a location outside the checkout (or into .git/). Tools that follow links can read or overwrite files on your machine; some checkouts have used this to plant hooks.

**Fix:** Delete the link or confirm the target is harmless.

### `GITATTRIBUTES-DRIVER` - .gitattributes references a custom filter/diff/merge driver

**Severity:** medium  

The attributes file assigns files to a filter=, diff= or merge= driver. Drivers are commands defined in git config; if that config also ships in the repo (GIT-CONFIG-TRAP) or you follow the README's `git config` instructions, Git executes them on checkout/diff/merge.

**Fix:** Check which driver is referenced and whether the README asks you to configure it.

### `GIT-HOOKS-DIR` - Hook scripts shipped in the repo (inactive until configured)

**Severity:** low  

A .githooks/, .husky/, hooks/ or similar directory contains Git hook scripts. They only run after `git config core.hooksPath …`, `npm install` (husky), `pre-commit install`, or `lefthook install`.

**Fix:** Fine to keep; just read them before running the project's install step.

## Install & build - runs on npm install, pip install, cd, cargo build, commit, CI

| Rule | Default severity | What it finds |
|---|---|---|
| `CARGO-CONFIG-EXEC` | high | Cargo config overrides the compiler, linker, runner or aliases |
| `GHA-UNSAFE-WORKFLOW` | high | GitHub Actions workflow is injectable or runs untrusted PR code |
| `NPM-LIFECYCLE` | high | npm lifecycle script runs on install |
| `PKG-REGISTRY-OVERRIDE` | high | Package manager config redirects downloads or disables protections |
| `PY-INSTALL-HOOK` | high | Python packaging file executes code on install |
| `SHELL-AUTOLOAD` | high | File is auto-sourced by the shell when you cd into the directory |
| `CONTAINER-HOST-ESCAPE` | medium | Compose/Docker config mounts the host or runs privileged |
| `OS-TRAP-FILE` | medium | File that executes or leaks credentials when viewed or double-clicked |
| `PRECOMMIT-LOCAL-HOOK` | medium | pre-commit config runs a local command |

### `CARGO-CONFIG-EXEC` - Cargo config overrides the compiler, linker, runner or aliases

**Severity:** high  

.cargo/config.toml sets rustc, rustc-wrapper, linker, runner, or an [alias]. `cargo build`/`cargo run`/`cargo test` then execute a program chosen by the repository, often a path inside the repo.

**Fix:** Delete .cargo/config.toml or inspect every path in it before running cargo.

### `GHA-UNSAFE-WORKFLOW` - GitHub Actions workflow is injectable or runs untrusted PR code

**Severity:** high  

A workflow uses pull_request_target/issue_comment/workflow_run together with a checkout of the PR head, or interpolates attacker-controlled context (issue title/body, PR title, head_ref, comment body) directly in `run:`. Relevant if you fork or maintain this repo: it leaks secrets to anyone who opens a PR.

**Fix:** Use an environment variable instead of inline ${{ }} in run:, and never check out PR code under pull_request_target.

### `NPM-LIFECYCLE` - npm lifecycle script runs on install

**Severity:** high  

package.json defines preinstall/install/postinstall/prepare. `npm install` (also yarn/pnpm/bun) runs it automatically, with your user privileges, before you have read any code.

**Fix:** Install with `npm install --ignore-scripts` first and read the script. For pnpm/yarn/bun, equivalent flags exist.

### `PKG-REGISTRY-OVERRIDE` - Package manager config redirects downloads or disables protections

**Severity:** high  

.npmrc/.yarnrc.yml/bunfig.toml/pip requirements/uv/poetry/cargo/Gemfile config points the package manager at a non-default registry, index or mirror, adds --find-links, or turns off script/hash protections. Dependencies then come from a server the repository author controls.

**Fix:** Compare the registry URL with the official one. Delete the override before installing.

### `PY-INSTALL-HOOK` - Python packaging file executes code on install

**Severity:** high  

setup.py calls os.system/subprocess/urllib/exec/eval/base64, pyproject.toml uses an in-tree build backend (backend-path) or an unknown build backend, or the repo ships sitecustomize.py/usercustomize.py/.pth files. These run on `pip install .`/`pip install -e .` – or, for .pth and sitecustomize, every time Python starts.

**Fix:** Read setup.py and the build backend before installing. Delete stray .pth / sitecustomize files.

### `SHELL-AUTOLOAD` - File is auto-sourced by the shell when you cd into the directory

**Severity:** high  

.envrc (direnv), .autoenv/.autoenv.zsh/.in (autoenv), .mise.toml/.rtx.toml hooks and tasks, or shell rc files committed to the repo. direnv and mise ask for a one-time `allow`/`trust`; autoenv runs immediately.

**Fix:** Read it before `direnv allow` / `mise trust`. Never source untrusted rc files.

### `CONTAINER-HOST-ESCAPE` - Compose/Docker config mounts the host or runs privileged

**Severity:** medium  

docker-compose.yml (or Dockerfile/Vagrantfile) requests privileged mode, the Docker socket, the host root filesystem, host network/PID, or a home directory mount. `docker compose up` then has your machine.

**Fix:** Review volumes/privileged/cap_add before starting the stack.

### `OS-TRAP-FILE` - File that executes or leaks credentials when viewed or double-clicked

**Severity:** medium  

Windows and macOS treat some files specially: .lnk/.scf/.url/desktop.ini/.library-ms leak NTLM hashes or run commands as soon as Explorer renders the folder; .hta/.vbs/.ps1/.cmd/.command run on double-click; .iso/.img bypass Mark-of-the-Web. They rarely belong in a source repository.

**Fix:** Do not open the folder in Explorer/Finder before deleting these files. Verify why they are in a code repo.

### `PRECOMMIT-LOCAL-HOOK` - pre-commit config runs a local command

**Severity:** medium  

.pre-commit-config.yaml defines `repo: local` hooks with language: system/script, or pulls hooks from an unusual URL. After `pre-commit install` they run on every commit.

**Fix:** Read the `entry:` commands before `pre-commit install`.

## AI coding agents - hooks, permissions, MCP servers, prompt injection

| Rule | Default severity | What it finds |
|---|---|---|
| `AGENT-HOOKS` | critical | AI agent hook executes shell commands automatically |
| `AGENT-HIDDEN-TEXT` | high | Hidden text in an agent instruction or doc file |
| `AGENT-INJECTION` | high | Agent instruction file contains prompt-injection or dangerous commands |
| `AGENT-PERMISSIONS` | high | Agent config pre-approves tools or bypasses permissions |
| `AGENT-PLUGIN-CODE` | high | Project ships executable agent plugin/extension code |
| `MCP-SERVER-CONFIG` | high | Project MCP config launches a local process or points at a remote server |

### `AGENT-HOOKS` - AI agent hook executes shell commands automatically

**Severity:** critical  

Project-level hook configuration (.claude/settings.json hooks, .cursor/hooks.json, .kiro/hooks, Gemini/Windsurf/Copilot hooks) makes the agent run a shell command on events like SessionStart, PreToolUse, file save or prompt submit – without the model or the user seeing it as a tool call.

**Fix:** Read every `command` in the hook file. Remove the file before starting an agent session here.

### `AGENT-HIDDEN-TEXT` - Hidden text in an agent instruction or doc file

**Severity:** high  

The file contains text invisible to a human reader but visible to a language model: HTML comments with imperative content, zero-width characters, Unicode tag characters (U+E0000-E007F 'ASCII smuggling'), long runs of variation selectors, bidi overrides, or white-on-white/`display:none` HTML.

**Fix:** View the file with `cat -A` or a hex viewer. Delete the hidden content.

### `AGENT-INJECTION` - Agent instruction file contains prompt-injection or dangerous commands

**Severity:** high  

CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md and similar files are fed to AI coding agents as trusted instructions. This one contains phrases that override the agent's rules, hide actions from the user, read credentials, pipe downloads into a shell, or disable permission checks.

**Fix:** Open the file and read it as if it were a shell script. Do not run an agent in this repo until it is clean.

### `AGENT-PERMISSIONS` - Agent config pre-approves tools or bypasses permissions

**Severity:** high  

Project settings grant the agent blanket permissions (e.g. Claude Code permissions.allow with Bash(*) or defaultMode bypassPermissions, enableAllProjectMcpServers, Gemini autoAccept/approvalMode yolo, Aider yes-always, Copilot/Cursor auto-run). Whoever opens the repo with that agent inherits the relaxed guardrails.

**Fix:** Delete or review the permissions block; keep project settings to formatting/style only.

### `AGENT-PLUGIN-CODE` - Project ships executable agent plugin/extension code

**Severity:** high  

Files under .opencode/plugin, .claude/plugins, .gemini/extensions, .cursor/extensions or similar are loaded and executed by the agent on start. They are code, not configuration.

**Fix:** Read the plugin source before starting the agent, or delete the directory.

### `MCP-SERVER-CONFIG` - Project MCP config launches a local process or points at a remote server

**Severity:** high  

A project-scoped MCP configuration (.mcp.json, .cursor/mcp.json, .vscode/mcp.json, .gemini/settings.json…) defines servers. stdio servers are *processes the agent spawns* with your privileges (npx -y …, uvx …, a script in the repo); remote servers receive everything the agent sends them. Most agents prompt once, then remember.

**Fix:** Check each `command`/`args`/`url`. Prefer well-known published servers pinned to a version.

## File content - hidden Unicode, download-and-run, decode-and-eval, exfil URLs, binaries

| Rule | Default severity | What it finds |
|---|---|---|
| `OBFUSCATED-EXEC` | high | Obfuscated or indirect code execution |
| `UNICODE-HIDDEN` | high | Invisible or direction-overriding Unicode in a source/config file |
| `BINARY-EXECUTABLE` | medium | Compiled executable committed to the repository |
| `FILENAME-CONFUSABLE` | medium | File or directory name uses look-alike Unicode characters |
| `PIPE-TO-SHELL` | medium | Download piped directly into an interpreter |
| `SUSPICIOUS-URL` | medium | URL to a webhook, tunnel, paste site, shortener or raw IP |

### `OBFUSCATED-EXEC` - Obfuscated or indirect code execution

**Severity:** high  

Code is decoded (base64/hex/char codes) and then evaluated, PowerShell is encoded or hidden, loader environment variables are set, or an OS protection is switched off. Legitimate projects rarely need to hide what they run.

**Fix:** Decode the payload yourself and read it before running anything in this repository.

### `UNICODE-HIDDEN` - Invisible or direction-overriding Unicode in a source/config file

**Severity:** high  

Bidirectional override characters (Trojan Source) make code read differently than it compiles; zero-width characters and Unicode tag characters hide text from humans while tools and language models still see it.

**Fix:** Open the file with `cat -A`/`less -U` or an editor that shows invisible characters, and remove them.

### `BINARY-EXECUTABLE` - Compiled executable committed to the repository

**Severity:** medium  

A file has an ELF/PE/Mach-O header. Binaries cannot be reviewed like source; one with a misleading extension (.png, .txt, .dat) is a strong signal of a hidden payload.

**Fix:** Check whether the project really needs to ship binaries; verify checksums against an official release.

### `FILENAME-CONFUSABLE` - File or directory name uses look-alike Unicode characters

**Severity:** medium  

A name mixes Latin letters with Cyrillic/Greek look-alikes (e.g. 'а' U+0430 for 'a') or contains control/zero-width characters. It can impersonate a trusted file name (README.md, package.json, .gitignore).

**Fix:** Rename or delete the file; check what the real file with that name contains.

### `PIPE-TO-SHELL` - Download piped directly into an interpreter

**Severity:** medium  

`curl … | sh`, `wget … | python`, `iwr … | iex`: whatever the server returns runs immediately, unreviewed. Harmless in a README that you read first; dangerous in anything that runs automatically.

**Fix:** Download to a file, read it, then run it.

### `SUSPICIOUS-URL` - URL to a webhook, tunnel, paste site, shortener or raw IP

**Severity:** medium  

Chat webhooks and request-catchers are classic exfiltration endpoints; tunnels, paste sites, shorteners and raw IP addresses hide where code or data really goes.

**Fix:** Resolve the URL (without visiting it) and ask why a code repository needs it.
