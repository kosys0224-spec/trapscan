# Contributing to trapscan

Thanks for helping. The most valuable contributions, in order:

1. **False-positive reports** with the file (or a redacted version) that triggered the finding. Calibration is what makes the tool usable.
2. **New rules** for an auto-execution path that is not covered yet. Every rule is one function in one file.
3. **Real-world trap samples** (defanged - replace payloads with `echo`) added to `examples/make_demo_repo.py` and the tests.

## Layout

```
src/trapscan/
  cli.py          argument parsing, exit codes
  scanner.py      Context (file walk + cached reads), ScanOptions, scan_path(), archive extraction
  findings.py     Finding / Rule dataclasses, @rule decorator, RULES registry
  report.py       text / JSON / SARIF renderers
  util.py         JSONC loader, git-config & TOML line parsers, binary sniffing
  rules/
    editors.py    VS Code, devcontainer, JetBrains, Vim, Emacs, other editors
    gitrules.py   .git/config, hooks, .gitattributes, .gitmodules, symlinks, .GIT look-alikes
    build.py      npm/pip/cargo/bundler, direnv/mise, pre-commit, GitHub Actions, Compose, OS trap files
    agents.py     Claude Code / Cursor / Copilot / Gemini / Windsurf / Kiro / Aider / MCP, prompt injection
    content.py    hidden Unicode, pipe-to-shell, decode-and-eval, suspicious URLs, binaries, confusable names
tests/test_trapscan.py   unittest suite (also runs under pytest)
examples/make_demo_repo.py   generates a harmless trapped repo
scripts/gen_rules_doc.py     regenerates docs/rules.md
scripts/make_screenshot.py   regenerates docs/demo.png (needs Playwright)
```

## Adding a rule

```python
from ..findings import Finding, Severity, rule

@rule(
    "MY-RULE-ID", Severity.HIGH, "One-line title shown in output", "install",   # category: editor|git|install|agent|content
    "Two or three sentences: what the file is, when it executes, why it matters.",
    "One sentence: what the user should do about it.",
)
def my_rule(ctx):
    r = my_rule.rule
    for fi in ctx.by_name("some.config"):            # or ctx.glob("**/.tool/*.json")
        text = ctx.text(fi)                          # None for binary / huge / unreadable
        if text and "dangerous" in text:
            yield r.hit(fi.rel, line=1, snippet="...", detail="specific reason", severity=Severity.MEDIUM)
```

Guidelines:

- **Default severity = worst realistic case.** Downgrade from evidence inside the rule (`severity=` on `hit`) rather than reporting everything at the top level. `critical` is reserved for "runs with no further user action in a default setup" (folderOpen task, `initializeCommand`, `core.fsmonitor`, agent hooks).
- **Every finding needs `file:line` and a snippet** where the format allows it. People need to be able to go look.
- **Prefer parsing over regex** for JSON-ish files (`load_jsonc`), git config (`parse_git_config`) and TOML (`parse_toml_lines`). Regex is fine for line-oriented formats.
- **Calibrate.** Run the rule over a few popular repositories of the relevant ecosystem (`git clone --depth 1 …; trapscan repo`) and make sure it is quiet. Mention what you tested in the PR.
- **Add a fixture** to `examples/make_demo_repo.py` (harmless payload) and an assertion in `tests/test_trapscan.py`; then run `python scripts/gen_rules_doc.py`.

## Running things

```bash
pip install -e .
python -m unittest -v                    # tests
trapscan . --exclude 'src/trapscan/rules/*'   # self-scan (the rule sources naturally trip the content rules)
python examples/make_demo_repo.py /tmp/demo && trapscan /tmp/demo
```

Code style: standard library only, type hints where cheap, lines ≤ 160. No new runtime dependencies - that is a feature.

## Commit messages and PRs

Use a short imperative subject (`Add rule for Gradle init scripts`). One rule or fix per PR keeps review quick. Fill in the PR template, especially the calibration section.
