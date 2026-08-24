# Negative-control fixtures

Deliberately broken policies. `scripts/lint_policies.py` runs each of these
through the linter **before** it looks at the real ones, and fails if any comes
back clean.

The point is narrow but important: a linter that reports "clean" tells you
nothing unless you know it is capable of reporting something else. A dependency
upgrade that silently defanged `parliament` would otherwise turn the whole check
into a green tick that verifies nothing — which is worse than having no check,
because it is trusted.

| Fixture | Failure class it proves the linter still catches |
| --- | --- |
| `bad-action.json` | Typo'd action names (`kms:Decrpyt`) |
| `bad-condition-operator.json` | A condition operator that does not exist (`StringEqualsIfExistss`) |
| `bad-condition-key.json` | A condition key meaningless for the action it is attached to |

All three are failure modes that hand-written `jsonencode` policies are prone to
and that `terraform validate` cannot see: each renders as perfectly valid JSON.
