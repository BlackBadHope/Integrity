# Agent instructions

## Cloud tasks: keep the Integrity journal

If the environment variable `INTEGRITY_CLOUD` is `1` (a cloud task prepared with
`examples/cloud-agents/codex-cloud-setup.sh`), follow the repository skill
[`integrity-cloud-journal`](.agents/skills/integrity-cloud-journal/SKILL.md) for
the whole task:

1. `integrity-cloud open` first.
2. For every request: `turn-open`, then `event` records, then `turn-close`.
3. `integrity-cloud seal --out integrity-journal/` before you finish, and commit
   the bundle.

Local sessions without `INTEGRITY_CLOUD=1` already have Integrity hooks and
should ignore this section.

## Tests

```bash
python -B -m pytest -q -p no:cacheprovider
python -B -m pytest -q -p no:cacheprovider --import-mode=importlib components/*/tests
```
