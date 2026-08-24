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

Scenario 4 is the scenario for which the brief requests a module, and it received the
majority of the effort. Scenarios 1-3 are also accompanied by code, because in each the
central claim is more readily demonstrated than argued: that the managed Config rule
cannot answer the question posed, that a private API removes the bypass rather than
blocking it, and that the alarms worth having are those which treat silence as failure.

---

## Reading order

The design notes for the backup module are in
[`docs/scenario-4-backup-policy.md`](docs/scenario-4-backup-policy.md), which sets out the
five decisions in the module that most warrant scrutiny.

The correctness logic itself is in
[`modules/backup-policy/plan.tf`](modules/backup-policy/plan.tf) and
[`modules/backup-policy/locals.tf`](modules/backup-policy/locals.tf). The input contract
and the guardrails that enforce it are in
[`modules/backup-policy/variables.tf`](modules/backup-policy/variables.tf); the
preconditions there carry the reasoning behind each constraint.

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

## Design decisions in the backup module

**Plan-time rejection of configurations AWS accepts and then fails on nightly.**
A Vault Lock enforces its retention window *at job time*, not at apply time. A plan whose
`delete_after` falls outside a destination's window applies cleanly, reports success, and
then fails every night in production, and on a compliance lock the window cannot be
widened to fix it. The module checks every `(rule, destination, retention)` triple against
*that destination's* window at plan time and names the offender. Five other run-time-only
AWS constraints get the same treatment.
[ADR-0003](docs/adr/0003-plan-time-retention-validation.md)

**Selection uses `condition`, not `selection_tag`.**
AWS Backup evaluates multiple `selection_tag` blocks with OR, so `ToBackup=true` **AND**
`Owner=<owner>` written that way accepts resources with no owner at all. It is invisible
in a plan diff, and it fails in the direction that breaks nothing: more resources are
protected than intended, so no job fails and the discrepancy surfaces only at audit.
[ADR-0002](docs/adr/0002-condition-not-selection-tag.md)

**The copy topology is a map rather than a fixed set of locations.**
Terraform cannot iterate over provider configurations, which is why modules like this are
usually hard-wired to a fixed set of locations, with the KMS key, the lock and the vault
policy copy-pasted per location. Using the AWS provider v6 per-resource `region` argument,
copy destinations are a map. Adding a Region is an entry, not a provider alias and a
copy of every resource. A test exercises the module with five destinations across five
Regions.
[ADR-0004](docs/adr/0004-module-composition-and-account-boundaries.md)

---

## Running the tests

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
| `backup-policy` | 64 |
| `backup-policy/modules/backup-vault` | 20 |
| `api-private-edge` | 27 |
| `gitlab-observability` | 20 |
| | **131** |

No AWS account or credentials are required. Every test runs against `mock_provider`,
which is what makes the suite usable as a required check on a pull request rather than a
scheduled job that is eventually disabled.

The Lambda supporting scenario 1 is tested the same way:

```bash
python3 -m unittest discover -s lambdas/kms-rotation-compliance/tests \
                             -t lambdas/kms-rotation-compliance
```

The policy linter is optional and requires `pip install parliament`:

```bash
python3 scripts/lint_policies.py
```

---

## Verification

| Check | Status |
| --- | --- |
| `terraform fmt` / `validate` | clean |
| `terraform test` - 131 tests, mocked provider | passing |
| Lambda unit tests - 36 tests | passing |
| `scripts/lint_policies.py` - every policy the backup module renders, through an IAM linter | 8/8 clean |

The policy linter renders the policies from a real `terraform plan` and checks them against
AWS's action and condition-key catalogue: typo'd action names, condition operators that do
not exist, condition keys meaningless for the action they are attached to. All of those
render as valid JSON and are invisible to `terraform validate`. It self-tests against three
deliberately broken fixtures first and fails if any comes back clean, since a linter
reporting "clean" carries no information unless it is known to be capable of reporting
something else.

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
  adr/                              Four decision records

modules/backup-policy/              Scenario 4: the module the brief asks for
  modules/backup-vault/             Leaf module: one vault + key + lock + policy
  examples/{minimal,complete}/      One account; and the full two-account topology
  tests/                            64 tests (20 more in the submodule)

modules/api-private-edge/           Scenario 2: private API through PrivateLink,
                                    split-horizon DNS, CloudFront front door
modules/gitlab-observability/       Scenario 3: synthetic canaries and the alarms
                                    whose silence indicates failure

lambdas/kms-rotation-compliance/    Scenario 1, Q3: the custom AWS Config rule, with
                                    36 unit tests requiring neither boto3 nor credentials

runbooks/backup-restore.md          Which of the three copies to restore from, and why
                                    that choice is not interchangeable

scripts/lint_policies.py            Renders and lints every policy the backup module
                                    produces
```

---

## Conventions

- Comments explain **why**, not what; the Terraform already states what.
- All identifiers, domains and account IDs are neutral placeholders (`example.com`,
  `111111111111`).
- Every guardrail has a test that feeds it a bad config and asserts the refusal.
