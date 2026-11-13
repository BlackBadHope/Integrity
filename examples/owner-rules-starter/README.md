# Example: a starter pack of owner rules

`owner_rules.json` holds 20 generic behaviour rules in the `owner-rule/v1`
format. It is an **example**: a starting point for your own rules, not a
policy this project applies to anyone.

An owner rule is a short standing instruction with a reason and a way to
follow it. The memory server can add the rules that fit the current request
to the admission capsule, so an agent sees them before it acts. See
[`src/integrity_guardian/owner_rules.py`](../../src/integrity_guardian/owner_rules.py).

## What is in the pack

- 4 rules are marked `always`: they are offered on every turn when nothing
  more specific matches.
- 16 rules are offered when the request matches their triggers (keywords in
  English and Russian, tool names).
- Every rule has the text in English and Russian (`rule_en`, `rule_ru`), a
  reason (`why`, `why_ru`) and a way to follow it (`how`, `how_ru`).
- The rules name no organisation, host, person or product.

| Rule | Always | In short |
|---|---|---|
| `reversible-decisions-yourself` | yes | Decide what can be undone; ask about what cannot |
| `prod-change-protocol` | yes | Production change: explicit go-ahead, rollback, checks, one step |
| `admit-mistake-fix-source` | yes | Say you were wrong and fix the source |
| `never-print-secrets` | yes | No secret value, part or length in output |
| `verify-before-proposing` | | Measure before you propose |
| `no-premature-questions` | | Ask at the real decision point |
| `chase-side-anomalies` | | Trace side anomalies or record them |
| `check-shared-resource-first` | | See who else works on a shared resource |
| `deploy-real-exec` | | Run the real file as the real user before deploying |
| `record-findings` | | Findings and decisions go to memory |
| `history-first-plans` | | Plans start from the decision history |
| `delegated-reads-parent` | | A delegated agent reads and quotes the approval |
| `factcheck-before-override` | | Read another agent's history before correcting it |
| `finish-not-idle` | | Carry permitted work to a verified result |
| `verify-at-source` | | Check facts at the source of truth |
| `baseline-not-before-after` | | Compare with a same-period baseline |
| `fresh-client-postcheck` | | Post-check a release from a fresh client |
| `no-rollback-dry-run` | | A rollback is not a dry run until proven |
| `delegate-reports-each-turn` | | A delegated agent reports every turn |
| `device-commands-from-registry` | | Device commands come from a verified registry |

## Try it

The selector is a pure function. From the repository root:

```bash
python - <<'EOF'
import json
from integrity_guardian.owner_rules import build_rule_index, select_owner_rules

records = json.load(open("examples/owner-rules-starter/owner_rules.json", encoding="utf-8"))["owner_rules"]
rules, receipt = select_owner_rules(build_rule_index(records), "deploy the hotfix to the production server")
print([rule["rule_id"] for rule in rules], receipt["bytes"])
EOF
```

`prod-change-protocol` comes first.

## Use it with a memory server

The server reads an index file only when both variables are set:

```bash
export INTEGRITY_OWNER_RULES=on
export INTEGRITY_OWNER_RULES_INDEX=/path/to/owner_rules.json
```

With the flag off, or with a missing or broken file, admission is unchanged.

## Make it yours

- Copy the file and edit it. Keep `rule_id` stable and raise `version` when
  you change a rule.
- Write the reason. A rule without a reason is followed blindly or not at all.
- Keep at most four `always` rules: the selector offers no more than four when
  nothing else matches.
- Keep names of people, hosts and customers out of a pack you plan to share.

## Enforcement

A rule in this pack is text. It does not block anything. Four rules carry a
`mechanism` note that points to a rule of the optional rule guard in
[`components/integrity-guards`](../../components/integrity-guards/README.md);
the guard is configured separately.

## Verified

`tests/test_example_owner_rules_starter.py` loads the pack, checks its shape
(20 rules, 4 `always`, both languages, no addresses), and checks that eight
requests in English and Russian select the expected rule on an empty memory.

## Not verified

- The pack was not run inside a live memory server in its published form.
- No measurement shows that agents follow these rules more often with the pack
  than without it.
