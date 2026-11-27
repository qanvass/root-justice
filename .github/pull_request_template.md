## What changed

<!-- A clear and concise summary of what this pull request changes and why. -->

- ...

## How it was tested

<!-- Describe the tests you ran and confirm the full offline suite passes: -->
- [ ] Ran `python -m unittest discover -s tests` locally and all tests pass.
- [ ] Added or updated deterministic, offline unit tests for any new behavior.

## Defensive scope & Project checklist

Please confirm your changes follow the rules in `CONTRIBUTING.md`:
- [ ] **No offensive or "hack-back" functionality** was added (strictly defensive scope, no third-party network calls, fail-open guarantee preserved).
- [ ] **Standard-library only** (no new runtime third-party dependencies added).
- [ ] **Backward compatible** (new parameters are keyword-only with safe defaults; existing public imports remain intact).
- [ ] Closes #<!-- issue number, if applicable -->
