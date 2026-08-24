# AWS Cloud Engineer — skills assessment

Responses to the four scenarios. Three are analyses; the fourth is a build.

| # | Scenario | Response |
| --- | --- | --- |
| 1 | Encryption management — KMS key rotation | [`docs/scenario-1-key-rotation.md`](docs/scenario-1-key-rotation.md) |
| 2 | APIs-as-a-product — public and private APIs | [`docs/scenario-2-api-exposure.md`](docs/scenario-2-api-exposure.md) |
| 3 | Resilience & monitoring — GitLab | [`docs/scenario-3-gitlab-resilience.md`](docs/scenario-3-gitlab-resilience.md) |
| 4 | Backup policy — **Terraform module** | [`modules/backup-policy`](modules/backup-policy) · [design notes](docs/scenario-4-backup-policy.md) |

Each analysis answers the scenario's four numbered questions in order, under headings
`Q1`–`Q4`, and ends with a one-line-per-question summary. Scenario 4 is the only one the
brief asks for code, and it is where most of the effort went.

---

## Where to start

If you have five minutes, read **[`docs/scenario-4-backup-policy.md`](docs/scenario-4-backup-policy.md)**
— it explains the five decisions in the module that are worth defending — and then look at
[`modules/backup-policy/plan.tf`](modules/backup-policy/plan.tf) and
[`modules/backup-policy/locals.tf`](modules/backup-policy/locals.tf), where the correctness
logic lives.

If you have twenty, add [`docs/review.md`](docs/review.md): the module was put through two
rounds of adversarial review, and that document records what was found, what changed, and
which questions could not be settled without a live AWS account.

---

## Scenario 4 — requirement coverage

| Requirement from the brief | Where |
| --- | --- |
| Plan definition — frequency | `rules[*].schedule` |
| Plan definition — retention | `rules[*].retention.delete_after`, and independently per copy destination |
| Plan definition — encryption | One customer managed key per vault; copies re-encrypted with a key in the destination |
| Resource selection — all supported resources | `selection_resources = ["*"]`, with a documented caveat about per-Region opt-in |
| Resource selection — `ToBackup=true` **AND** `Owner=<owner>` | A `condition` block, **not** `selection_tag` — see [ADR-0002](docs/adr/0002-condition-not-selection-tag.md) |
| Cross-Region copy — frequency, retention, key | `copy_destinations` + `rules[*].copy_to` |
| Cross-account copy — frequency, retention, key | An external destination, plus `modules/backup-vault` deployed in the backup account |
| WORM — Vault Lock preventing malicious and accidental deletion | Every vault; compliance mode available behind an explicit acknowledgement — see [ADR-0001](docs/adr/0001-vault-lock-compliance-mode.md) |

---

## Three things in the module worth a look

**It refuses configurations that AWS accepts and then fails on nightly.**
A Vault Lock enforces its retention window *at job time*, not at apply time. A plan whose
`delete_after` falls outside a destination's window applies cleanly, reports success, and
then fails every night in production — and on a compliance lock the window cannot be
widened to fix it. The module checks every `(rule, destination, retention)` triple against
*that destination's* window at plan time and names the offender. Five other run-time-only
AWS constraints get the same treatment.
[ADR-0003](docs/adr/0003-plan-time-retention-validation.md)

**Selection uses `condition`, not `selection_tag`.**
AWS Backup evaluates multiple `selection_tag` blocks with OR, so `ToBackup=true` **AND**
`Owner=<owner>` written that way silently accepts resources with no owner. It is invisible
in a plan diff and fails in the direction that breaks nothing — you back up more than
intended, so no job fails and nobody notices until an audit.
[ADR-0002](docs/adr/0002-condition-not-selection-tag.md)

**It scales past the three vaults in the brief.**
Terraform cannot iterate over provider configurations, which is why modules like this are
usually hard-wired to a fixed set of locations, with the KMS key, the lock and the vault
policy copy-pasted per location. Using the AWS provider v6 per-resource `region` argument,
copy destinations are a map — adding a Region is an entry, not a provider alias and a copy
of every resource. A test runs the module with five destinations across five Regions.
[ADR-0004](docs/adr/0004-module-composition-and-account-boundaries.md)

---

## Running it

Terraform `>= 1.9`, AWS provider `>= 6.0, < 7.0`. The v6 floor is deliberate: the
per-resource `region` argument is what makes the copy topology a map.

```bash
cd modules/backup-policy
terraform init
terraform test        # 63 tests

cd modules/backup-vault
terraform init && terraform test   # 20 more
```

**No AWS account or credentials are needed.** All 83 tests run against `mock_provider`,
which is what makes them usable as a required check rather than a nightly job someone
turns off.

The Lambda supporting scenario 1 tests the same way:

```bash
python3 -m unittest discover -s lambdas/kms-rotation-compliance/tests \
                             -t lambdas/kms-rotation-compliance
```

Optionally, the policy linter — needs `pip install parliament`:

```bash
python3 scripts/lint_policies.py
```

---

## What has actually been verified

| Check | Status |
| --- | --- |
| `terraform fmt` / `validate` | clean |
| `terraform test` — 83 tests, mocked provider | passing |
| Lambda unit tests — 28 tests | passing |
| `scripts/lint_policies.py` — every rendered policy through an IAM linter | 8/8 clean |

The policy linter renders the policies from a real `terraform plan` and checks them against
AWS's action and condition-key catalogue. It self-tests against three deliberately broken
fixtures first and fails if any comes back clean — a linter reporting "clean" is worth
nothing unless you know it can report something else.

What none of this covers is whether AWS's authorisation engine evaluates the policies the
way they are intended. That needs a live account, and the specific open questions are
listed in [`docs/review.md`](docs/review.md) rather than assumed away. Local AWS emulators
were considered and rejected for it; the reasoning is in the same document.

---

## Contents

```
docs/
  scenario-1-key-rotation.md        Q1-Q4: BYOK rotation, the 25-rotation quota, the
                                    custom Config rule, HSM-to-KMS transport
  scenario-2-api-exposure.md        Q1-Q4: the regional-endpoint bypass, private APIs
                                    with split-horizon DNS, path-based routing, mitigations
  scenario-3-gitlab-resilience.md   Q1-Q4: single-AZ weaknesses and snapshot split-brain,
                                    target architectures, monitoring, runbook automation
  scenario-4-backup-policy.md       Design notes for the module
  review.md                         Two rounds of adversarial review and the response
  adr/                              Four decision records

modules/backup-policy/              Scenario 4. The build.
  modules/backup-vault/             Leaf module: one vault + key + lock + policy
  examples/{minimal,complete}/      One account; and the full two-account topology
  tests/                            63 tests (20 more in the submodule)

lambdas/kms-rotation-compliance/    Scenario 1, Q3: the custom AWS Config rule, with
                                    28 unit tests that need no boto3 and no credentials

runbooks/backup-restore.md          Which of the three copies to restore from, and why
                                    that choice is not interchangeable

scripts/lint_policies.py            Renders and lints every policy the module produces
```

---

## Conventions

- Comments explain **why**, not what. The Terraform already says what.
- All identifiers, domains and account IDs are neutral placeholders (`example.com`,
  `111111111111`).
- Every guardrail has a test that supplies a bad configuration and asserts the refusal. A
  guardrail with no test proving it fires is decoration.
