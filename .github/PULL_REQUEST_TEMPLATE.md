## What

<!-- One or two sentences. Link the issue if there is one. -->

## Type

- [ ] New rule
- [ ] False-positive fix / severity calibration
- [ ] Bug fix
- [ ] Docs / tooling

## Checklist

- [ ] `python -m unittest discover -s tests` passes
- [ ] New or changed rule has a fixture in `examples/make_demo_repo.py` and a test
- [ ] `python scripts/gen_rules_doc.py` was run if a rule's id, title, severity, description or fix changed
- [ ] No new runtime dependencies

## Calibration (for rule changes)

<!-- Which real repositories did you scan, and what did the rule report on them? -->
