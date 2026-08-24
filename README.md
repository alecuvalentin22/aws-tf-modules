# AWS Cloud Engineer - skills assessment

Alecu Valentin, August 2026

Responses to the four scenarios. Each written answer addresses the scenario's numbered
questions in order under headings `Q1`-`Q4`, and ends with a one-line-per-question
summary.

| # | Scenario | Written answer | Code |
| --- | --- | --- | --- |
| 1 | Encryption management - KMS key rotation | [`docs/scenario-1-key-rotation.md`](docs/scenario-1-key-rotation.md) | [`lambdas/kms-rotation-compliance`](lambdas/kms-rotation-compliance) |
| 2 | APIs-as-a-product - public and private APIs | [`docs/scenario-2-api-exposure.md`](docs/scenario-2-api-exposure.md) | [`modules/api-private-edge`](modules/api-private-edge) |
| 3 | Resilience and monitoring - GitLab | [`docs/scenario-3-gitlab-resilience.md`](docs/scenario-3-gitlab-resilience.md) | [`modules/gitlab-observability`](modules/gitlab-observability) |
| 4 | Backup policy | [`docs/scenario-4-backup-policy.md`](docs/scenario-4-backup-policy.md) | [`modules/backup-policy`](modules/backup-policy) |

Scenario 4 is the one the brief asks for a module, and it is where most of the effort
went. The code accompanying scenarios 1 to 3 is there because each written answer makes
a specific claim that is better demonstrated than asserted: that the AWS managed Config
rule cannot answer the question asked, that a private API removes the bypass outright,
and that the alarms which matter are the ones treating silence as failure.

---

## Where to start

If you have five minutes, read **[`docs/scenario-4-backup-policy.md`](docs/scenario-4-backup-policy.md)**
- it explains the five decisions in the module that are worth defending - and then look at
[`modules/backup-policy/plan.tf`](modules/backup-policy/plan.tf) and
[`modules/backup-policy/locals.tf`](modules/backup-policy/locals.tf), where the correctness
logic lives.

If you have twenty, add [`docs/review.md`](docs/review.md): the module was reviewed twice
against its own claims, and that document records what the reviews found, what changed in
response, and the trade-offs that were accepted rather than fixed.

---

## Scenario 4 - requirement coverage

| Requirement from the brief | Where |
| --- | --- |
| Plan definition - frequency | `rules[*].schedule` |
| Plan definition - retention | `rules[*].retention.delete_after`, and independently per copy destination |
| Plan definition - encryption | One customer managed key per vault; copies re-encrypted with a key in the destination |
| Resource selection - all supported resources | `selection_resources = ["*"]`, with a documented caveat about per-Region opt-in |
| Resource selection - `ToBackup=true` **AND** `Owner=<owner>` | A `condition` block, **not** `selection_tag` - see [ADR-0002](docs/adr/0002-condition-not-selection-tag.md) |
| Cross-Region copy - frequency, retention, key | `copy_destinations` + `rules[*].copy_to` |
| Cross-account copy - frequency, retention, key | An external destination, plus `modules/backup-vault` deployed in the backup account |
| WORM - Vault Lock preventing malicious and accidental deletion | Every vault; compliance mode available behind an explicit acknowledgement - see [ADR-0001](docs/adr/0001-vault-lock-compliance-mode.md) |

---

## Three things in the backup module worth a look

**It refuses configurations that AWS accepts and then fails on nightly.**
A Vault Lock enforces its retention window *at job time*, not at apply time. A plan whose
`delete_after` falls outside a destination's window applies cleanly, reports success, and
then fails every night in production - and on a compliance lock the window cannot be
widened to fix it. The module checks every `(rule, destination, retention)` triple against
*that destination's* window at plan time and names the offender. Five other run-time-only
AWS constraints get the same treatment.
[ADR-0003](docs/adr/0003-plan-time-retention-validation.md)

**Selection uses `condition`, not `selection_tag`.**
AWS Backup evaluates multiple `selection_tag` blocks with OR, so `ToBackup=true` **AND**
`Owner=<owner>` written that way silently accepts resources with no owner. It is invisible
in a plan diff and fails in the direction that breaks nothing - you back up more than
intended, so no job fails and nobody notices until an audit.
[ADR-0002](docs/adr/0002-condition-not-selection-tag.md)

**It scales past the three vaults in the brief.**
Terraform cannot iterate over provider configurations, which is why modules like this are
usually hard-wired to a fixed set of locations, with the KMS key, the lock and the vault
policy copy-pasted per location. Using the AWS provider v6 per-resource `region` argument,
copy destinations are a map - adding a Region is an entry, not a provider alias and a copy
of every resource. A test runs the module with five destinations across five Regions.
[ADR-0004](docs/adr/0004-module-composition-and-account-boundaries.md)

---

## Running it

Terraform `>= 1.9`, AWS provider `>= 6.0, < 7.0`. The v6 floor is deliberate: the
per-resource `region` argument is what makes the copy topology a map.

```bash
for dir in modules/backup-policy \
           modules/backup-policy/modules/backup-vault \
           modules/api-private-edge \
           modules/gitlab-observability; do
  ( cd "$dir" && terraform init -input=false && terraform test )
done
```

| Module | Tests |
| --- | --- |
| `backup-policy` | 63 |
| `backup-policy/modules/backup-vault` | 20 |
| `api-private-edge` | 15 |
| `gitlab-observability` | 12 |
| | **110** |

**No AWS account or credentials are needed.** Every test runs against `mock_provider`,
which is what makes them usable as a required check rather than a nightly job someone
turns off.

The Lambda supporting scenario 1 tests the same way:

```bash
python3 -m unittest discover -s lambdas/kms-rotation-compliance/tests \
                             -t lambdas/kms-rotation-compliance
```

Optionally, the policy linter - needs `pip install parliament`:

```bash
python3 scripts/lint_policies.py
```

---

## What has actually been verified

| Check | Status |
| --- | --- |
| `terraform fmt` / `validate` | clean |
| `terraform test` - 110 tests, mocked provider | passing |
| Lambda unit tests - 28 tests | passing |
| `scripts/lint_policies.py` - every rendered policy through an IAM linter | 8/8 clean |

The policy linter renders the policies from a real `terraform plan` and checks them against
AWS's action and condition-key catalogue: typo'd action names, condition operators that do
not exist, condition keys meaningless for the action they are attached to. All of those
render as valid JSON and are invisible to `terraform validate`. It self-tests against three
deliberately broken fixtures first and fails if any comes back clean, because a linter
reporting "clean" is worth nothing unless you know it can report something else.

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
  review.md                         Two rounds of review findings and the response to each
  adr/                              Four decision records

modules/backup-policy/              Scenario 4. The build.
  modules/backup-vault/             Leaf module: one vault + key + lock + policy
  examples/{minimal,complete}/      One account; and the full two-account topology
  tests/                            63 tests (20 more in the submodule)

modules/api-private-edge/           Scenario 2: private API through PrivateLink,
                                    split-horizon DNS, CloudFront front door
modules/gitlab-observability/       Scenario 3: canaries and the alarms that matter

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
