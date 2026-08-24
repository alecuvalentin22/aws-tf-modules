# AWS Cloud Engineer — skills assessment

Four scenario responses. Three are architecture and operations analyses; the fourth is a
build, and it is the centrepiece.

| # | Scenario | Response |
| --- | --- | --- |
| 1 | Encryption management — KMS key rotation | [`docs/scenario-1-key-rotation.md`](docs/scenario-1-key-rotation.md) |
| 2 | APIs as a product — public and private APIs | [`docs/scenario-2-api-exposure.md`](docs/scenario-2-api-exposure.md) |
| 3 | Resilience and monitoring — GitLab | [`docs/scenario-3-gitlab-resilience.md`](docs/scenario-3-gitlab-resilience.md) |
| 4 | Backup policy — **Terraform module** | [`modules/backup-policy`](modules/backup-policy) · [design notes](docs/scenario-4-backup-policy.md) |

Each analysis answers the brief's numbered questions in order and ends with a
one-line-per-question summary.

---

## Scenario 4 — the module

```
modules/backup-policy/
├── modules/backup-vault/    one vault: CMK + key policy + Vault Lock + access policy + notifications
├── plan.tf                  tiered rules, copy actions, tag-driven selection
├── vaults.tf                composes backup-vault: primary + N copy destinations
├── iam.tf                   service role
├── notifications.tf         SNS, EventBridge, failure and staleness alarms
├── restore-testing.tf       scheduled restore testing
├── audit.tf                 Audit Manager framework and report plans
├── examples/                minimal (one account) and complete (two accounts)
└── tests/                   26 tests; 8 more in the submodule
```

Three things in it are worth a look before the rest:

**It refuses configurations that AWS accepts and then fails on nightly.** A Vault Lock
enforces its retention window *at job time*. A plan whose `delete_after` falls outside a
destination's window applies cleanly and then fails every night in production, and on a
compliance lock the window cannot be widened to fix it. The module checks every
`(rule, destination, retention)` triple against **that destination's** window at plan
time and names the offender. Five more run-time-only AWS constraints get the same
treatment. [ADR-0003](docs/adr/0003-plan-time-retention-validation.md)

**Selection uses `condition`, not `selection_tag`.** Multiple `selection_tag` blocks are
OR-ed by AWS Backup, so `ToBackup=true` **AND** `Owner=<owner>` written that way silently
accepts resources with no owner. It is invisible in a plan diff and fails in the
direction that breaks nothing. [ADR-0002](docs/adr/0002-condition-not-selection-tag.md)

**It scales past the three vaults in the brief.** Terraform cannot iterate over provider
configurations, which is why modules like this are usually hard-wired to a fixed set of
locations. Using the AWS provider v6 per-resource `region` argument, copy destinations
are a map — adding a Region is an entry, not a provider alias and a copy of every
resource. A test runs it with five destinations.
[ADR-0004](docs/adr/0004-module-composition-and-account-boundaries.md)

### Running it

```bash
cd modules/backup-policy
terraform init
terraform test      # 54 tests, mocked provider, no AWS account needed

cd modules/backup-vault
terraform init && terraform test   # 19 more
```

All tests use `mock_provider`, so they need no credentials and run as a required CI
check. They caught real bugs during development — a `count` derived from a value unknown
until apply (which would have failed the very first plan in a fresh account, and never
again), and an unknown copy destination crashing on a map index before the friendly
precondition could produce its message. Neither is visible to `terraform validate`.

The module was then put through an adversarial review by a second agent briefed to break
it. That found three more silent failures — a vault policy that denied its own
replacement, restore-testing selections that matched nothing, and SNS topics encrypted
with a key no AWS service can publish through — none of which fail at apply time. All
are fixed, each with a regression test. [`docs/review.md`](docs/review.md) records what
was found and what changed.

---

## Operations

[`runbooks/backup-restore.md`](runbooks/backup-restore.md) — restoring from the backup
policy, including which of the three copies to use and why that choice is not
interchangeable.

## Decision records

| ADR | Decision |
| --- | --- |
| [0001](docs/adr/0001-vault-lock-compliance-mode.md) | Vault Lock: compliance mode is the target, governance is the default, and the code enforces the order |
| [0002](docs/adr/0002-condition-not-selection-tag.md) | Resource selection uses `condition` (AND), never `selection_tag` (OR) |
| [0003](docs/adr/0003-plan-time-retention-validation.md) | Validate retention against Vault Lock windows at plan time |
| [0004](docs/adr/0004-module-composition-and-account-boundaries.md) | A leaf vault module, the provider `region` argument, and two states across the account boundary |

[`docs/review.md`](docs/review.md) records the adversarial review of the module and the
response to each finding.

---

## Conventions

- Terraform `>= 1.9`, AWS provider `>= 6.0, < 7.0`. The v6 floor is deliberate — the
  per-resource `region` argument is what makes the copy topology a map.
- `terraform fmt`, `validate` and `test` run in CI on every push
  ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).
- Comments explain **why**, not what. The Terraform already says what.
- All identifiers, domains and account IDs are neutral placeholders (`example.com`,
  `111111111111`). Nothing here identifies a client.
