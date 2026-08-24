# Scenario 4 - AWS Backup Terraform module

> Implement a cloud backup policy on AWS using AWS Backup. Automation is key when
> deploying at scale. The design, validated by security, compliance and architecture:
> a backup module fed by a plan definition and a resource selection, writing into a
> Prod account (Frankfurt + Ireland) and an isolated Backup account (Frankfurt), with
> Vault Lock on every vault.
>
> Requirements: **plan definition** (frequency, retention, encryption); **resource
> selection** (all supported resources with `ToBackup=true` and `Owner=<owner>`);
> **cross-Region and cross-account copy** with defined frequency, retention and key;
> **WORM protection** via Vault Lock.

The module is at [`modules/backup-policy`](../modules/backup-policy). This document
explains the decisions in it. The [module README](../modules/backup-policy/README.md)
covers usage.

---

## Requirement coverage

| Requirement | Where | Note |
| --- | --- | --- |
| Backup frequency | `rules[*].schedule` | Per tier; cron or rate, with an explicit timezone |
| Backup retention | `rules[*].retention.delete_after` | Per tier, and independently per copy destination |
| Backup encryption | One CMK per vault | Cross-Region and cross-account copies are re-encrypted with a key in the destination |
| All supported resources | `selection_resources = ["*"]` | Plus a note on `aws_backup_region_settings` - see "What `*` does not mean" below |
| `ToBackup=true` **AND** `Owner=<owner>` | `condition` block | **Not** `selection_tag`. See ADR-0002 |
| Cross-Region copy, defined frequency/retention/key | `copy_destinations` + `rules[*].copy_to` | Frequency is expressed as which rule owns the copy - see below |
| Cross-account copy, defined frequency/retention/key | External destination + `modules/backup-vault` in the backup account | |
| WORM / Vault Lock | Every vault, compliance mode available | See ADR-0001 |

---

## The five decisions worth explaining

### 1. `condition`, not `selection_tag` - the correctness crux

The requirement is `ToBackup=true` **AND** `Owner=<owner>`.

AWS Backup evaluates **multiple `selection_tag` blocks with OR**. Written that way, a
resource tagged `ToBackup=true` and nothing else is selected, the ownership
requirement does nothing at all. `condition` entries are evaluated with **AND**,
which is what the requirement asks for.

This is the single most consequential correctness decision in the module, it is
invisible in a `terraform plan` diff, and it fails in the safe-looking direction: you
back up *more* than intended, so nothing breaks and nobody notices. Full reasoning in
[ADR-0002](adr/0002-condition-not-selection-tag.md); asserted by a test in
`tests/defaults.tftest.hcl`, including an assertion that `selection_tag` is not used
at all.

### 2. Copy frequency is expressed as which rule carries the copy

The brief asks for cross-Region and cross-account copy "with defined frequency".
**AWS Backup has no independent copy frequency** - a `copy_action` inherits the
schedule of the rule that owns it.

So a distinct copy cadence is expressed as a distinct rule, and `copy_to` is per-rule
rather than per-plan. The default:

| Tier | Schedule | Local | Cross-Region | Cross-account |
| --- | --- | --- | --- | --- |
| daily | 02:00 daily | 35 days | 35 days | - |
| weekly | 03:00 Sunday | 90 days | 90 days | 90 days |
| monthly | 04:00 on the 1st | 7 years, cold after 90d | 365 days | 7 years, cold after 90d |

That is a deliberate cost/assurance trade-off, not a limitation. Copying every daily
recovery point into a second account roughly triples storage for the tier least likely
to be the one restored from. The long-lived tiers are the ones worth putting behind an
account boundary, because those are the ones that survive a ransomware dwell time.

The module exposes `effective_copy_matrix` as an output for exactly this reason: the
copy topology is the part of a backup policy most often misread from the Terraform, and
it belongs in the change record in plain form.

### 3. Vault Lock retention windows are checked at plan time

The nastiest trap in AWS Backup:

> A vault's Vault Lock enforces `min_retention_days` / `max_retention_days` **on every
> incoming backup and copy job, at run time**. A plan whose retention falls outside
> that window applies cleanly, reports success, and then fails **every night, in
> production**, long after anyone is watching the apply.

And on a compliance-mode lock the window cannot be widened afterwards to fix it.

The module computes every `(rule, destination, delete_after)` triple against the lock
window of that specific destination, and fails at plan time with a message naming the
rule and the destination:

```
rule "monthly" -> destination backup_account: delete_after=2555 is outside
the vault lock window [7, 365]
```

Checking **per destination** rather than against one global window is what catches the
case where the local backup is fine and only the cross-account copy is rejected, the
version of this bug that is hardest to spot, because the plan appears to be working.

For an external (cross-account) destination the module cannot read the lock, so the
caller declares it via `lock_min_retention_days` / `lock_max_retention_days`. Omitting
both is an **error** rather than a silent skip, failing open with no signal on the least
observable hop defeats the point of the guardrail. `unvalidated_retention_targets` names
anything that went unchecked, including a deliberately unlocked primary vault.

Six tests in `tests/guardrails.tftest.hcl` cover this, including the accept case.

### 4. Governance mode first, and the code enforces the order

Compliance mode is the only setting that survives an attacker holding administrator
credentials, which is the entire reason a separate backup account exists. Governance
mode is removable by anyone with sufficient IAM permissions, so against that threat it
offers nothing.

But compliance mode is also irreversible, and the costs are real:

- Retention cannot be shortened. A mistaken `min_retention_days` of 2555 is a
  seven-year financial commitment.
- `terraform destroy` fails while the vault holds recovery points.
- No principal, including the account root and AWS Support, can undo it.

So the module defaults to **governance**, and refuses to create a compliance lock
unless `confirm_irreversible_compliance_lock = true` is set explicitly. That turns
"read the README before you apply this" into something the code enforces. The rollout
order is: apply in governance mode, prove a full backup -> copy -> **restore** cycle,
then flip. [ADR-0001](adr/0001-vault-lock-compliance-mode.md).

### 5. Restore testing

`aws_backup_restore_testing_plan` restores a real recovery point on a schedule, records
whether it worked and how long it took, and cleans up afterwards.

Nothing else in this module tells you whether the data can be read back. Vault Lock
proves the recovery points still exist; cross-account copy proves they exist somewhere
else; only a restore proves they are usable. It is also what turns an RTO from a design
claim into a measured number.

The testing plan covers the in-account copy destinations too, not only the primary vault
- a copy nobody has ever restored from is an assumption, not a second line of defence.
One plan per Region, because restore testing is regional and a plan cannot select a vault
in another Region.

The **cross-account** copy is the exception, and the reason is structural rather than an
oversight: it lives in an account this module has no credentials for. Testing it means
running a restore testing plan in the backup account, as part of that account's own
deployment. That is called out in the runbook because it is the copy you would reach for
during a ransomware incident, the worst one to be restoring from for the first time.

---

## Things the brief did not ask for, and why they are in anyway

The brief says the module "does not necessarily need to be production-ready". These
are included because without them the module produces compliance paperwork rather than
a working control:

| Addition | Why |
| --- | --- |
| SNS + EventBridge on failures | A backup policy that fails without telling anyone produces the paperwork of compliance and none of the data |
| **Staleness alarm** (`treat_missing_data = "breaching"`) | A plan that stops running emits **no failure events**. This is the only alarm that sees a deleted selection, a revoked role, or a resource type that was never opted in |
| Restore testing | See above |
| Audit Manager framework | Turns each requirement into a continuously evaluated control, so compliance is evidence rather than assertion |
| Least-privilege service role | AWS managed policies for coverage, plus explicit KMS and copy grants for the cross-Region and cross-account paths the managed policies do not fully cover |
| Deny-delete vault policy | Defence in depth behind Vault Lock, and the only deletion control in effect during the governance-mode validation window |

The staleness alarm deserves the emphasis. Every other alarm here detects a *bad*
backup. Only this one detects the absence of backups, which is both the more likely
failure and the one that looks fine on a dashboard.

---

## What `resources = ["*"]` does not mean

`["*"]` covers every resource type **that is opted in for that Region**. A type that
is not opted in is skipped without an error. The plan reports success while protecting
less than it appears to.

`aws_backup_region_settings` controls this, and the module can manage it
(`opt_in_resource_types`) but **leaves it null by default**. The setting is an
account-and-Region **singleton**: two Terraform states that both manage it will fight,
each apply reverting the other, and the symptom is intermittent unprotected resource
types rather than an obvious error.

The right owner is the account baseline, once. The variable exists for the case where
this module genuinely is that single owner. `aws_backup_global_settings`
(`isCrossAccountBackupEnabled`) is the same kind of singleton, is only valid from the
Organizations management account, and is off by default for the same reason.

This is a case where the more "complete" default is the more dangerous one.

---

## Module structure, and why it is two modules

```
modules/backup-policy/
+-- modules/backup-vault/     leaf: one vault + KMS key + lock + policy + notifications
+-- plan.tf                   rules, copy actions, selection
+-- vaults.tf                 composes backup-vault: primary + N copy destinations
+-- iam.tf                    service role
+-- notifications.tf          SNS, EventBridge, alarms
+-- restore-testing.tf        restore testing plan and selections
+-- audit.tf                  Audit Manager framework and reports
+-- examples/{minimal,complete}/
+-- tests/                    26 tests, mocked provider, no AWS account needed
```

Terraform cannot iterate over provider configurations. That single constraint is
why most AWS Backup modules are hard-wired to a fixed set of locations, with a copy of
the KMS key, the lock and the vault policy per location, three near-identical blocks
that then drift apart.

Two things avoid that here:

1. **The AWS provider v6 `region` argument.** Every resource takes a per-resource
   Region, so the module places vaults in **any number of Regions of the same account
   from one provider configuration**, driven by a map. Adding a fourth Region is a map
   entry; a test in `tests/scaling.tftest.hcl` runs the module with five destinations
   to prove it.
2. **The `backup-vault` leaf module.** The key policy, lock, deny-delete policy and
   notification wiring are written once and cannot drift between locations.

Cross-account still needs an aliased provider, because a different account needs
different credentials. That boundary is respected rather than papered over: the backup
account's vault is a separate instantiation of `backup-vault`, and its ARN is passed
in as an external destination.

In production those should be **two states**. A single state that can write to both
accounts is a single credential that can destroy both copies, which is precisely the
failure the isolated backup account exists to survive. The `complete` example wires
both into one apply for demonstration and says so in a comment; the module does not
require it.

---

## Testing

83 tests across the two modules, all against a **mocked provider** - no AWS account,
no credentials, so they run as a required check in CI:

The breakdown by file is in the module README. The guardrail suite is the one worth
reading: each of its cases was written by feeding the module a configuration AWS would
accept and then choke on nightly.

Policies are built with `jsonencode` rather than `aws_iam_policy_document` so that they
can be tested at all. A mocked provider cannot compute a data source, so a policy built
that way renders as an empty placeholder and nothing in it is checked, including the four
grants that decide whether a cross-account copy works.

Two tests caught real bugs during development:

- `count` derived from an SNS topic ARN that is unknown until apply - which would have
  failed the **very first** `terraform plan` in a fresh account, and never after.
- An unknown `copy_to` destination crashing on a map index in `locals.tf` before the
  friendly precondition could produce its message.

Both are the kind of defect that `terraform validate` cannot see.

## What review turned up

Going back over the module trying to break it, rather than to read it, found three
failures that all apply cleanly and only misbehave later:

| Found | Effect |
| --- | --- |
| The deny-delete vault policy denied `PutBackupVaultAccessPolicy` and `DeleteBackupVaultAccessPolicy` to `Principal: *` | The policy could never be corrected or removed by the role that created it, and `terraform destroy` could never succeed |
| Restore-testing selections filtered on `aws:ResourceTag/BackupRule` | That is a recovery-point tag, and `protected_resource_conditions` filters the protected resource. Every restore test selected zero resources, ran weekly, and reported success |
| SNS topics encrypted with `alias/aws/sns` | The AWS-managed key grants no service principal `kms:GenerateDataKey*`, so every notification and alarm failed at delivery, including the staleness alarm |

Three more came out of the same pass: a missing IAM grant on the destination key that
would have broken every encrypted cross-account copy, a `__primary__` sentinel key
collision that let the retention guardrail fail open, and a `copy_retention` override
that dropped `cold_storage_after`, turning a seven-year copy into warm storage.

A second pass over the fixes found that some of them had introduced problems of their
own. The worst was an acknowledgement flag covering two unrelated guards, so an unlocked
sandbox Region waived the cross-account KMS requirement as a side effect.

All of it is fixed and each has a regression test.

---

## Cost model

Order-of-magnitude, for roughly 10 TB of protected data in `eu-central-1`. The point is
the **shape**, not the absolute numbers.

| Component | Driver | Relative |
| --- | --- | --- |
| Primary warm storage (35d daily) | GB-month | 1.0x |
| Cross-Region copy | Storage + inter-Region transfer | ~1.2x |
| Cross-account copy (weekly + monthly only) | Storage | ~0.4x |
| Monthly tier in cold storage after 90d | GB-month, ~1/5 of warm | ~0.3x |
| Restore testing | Restore + short-lived resources | <0.05x |

Two things drive most of the bill and most of the available savings:

- **Which tiers copy where.** Copying dailies cross-account rather than only weeklies
  and monthlies would roughly double the cross-account line for very little assurance
  gain. That is the trade-off in decision 2.
- **Cold storage on the long tier.** The seven-year tier is the largest by volume, and
  the 90-day transition is what makes it affordable. Two AWS constraints shape it. The
  module enforces the first: `delete_after` must be at least 90 days after
  `cold_storage_after`, because the archive tier has a 90-day minimum charge, so
  deleting earlier costs *more*.

  The second it cannot enforce, and it is the one that breaks the arithmetic above. Cold
  storage applies to some resource types and not others: EBS, EFS, DynamoDB, Timestream
  and VMware tier, while RDS, Aurora, DocumentDB, Neptune, FSx and EC2 do not. Against
  `resources = ["*"]` the untiered types stay in warm storage for the full seven years at
  roughly five times the modelled cost, with nothing in the plan, the console or the bill
  to attribute it. Price the long tier against the real resource mix rather than against
  this table, and if the estate is mostly RDS, shorten it.

Restore testing is close to free relative to the storage and is the highest-value line
item here.

---

## Deployment order

1. **Backup account**: deploy `modules/backup-vault` with
   `source_account_ids = [<prod account>]`, `lock.mode = "governance"`. Note the ARN.
2. **Organizations management account**: enable cross-account backup
   (`isCrossAccountBackupEnabled`). Nothing copies cross-account until this is on.
3. **Account baseline**: opt in the AWS Backup resource types per Region, once.
4. **Prod account**: deploy `modules/backup-policy` with the backup account's vault ARN
   as an external destination, still in governance mode.
5. **Validate**: wait for a full cycle. Confirm backup jobs succeed, both copies land,
   the restore test passes, and the alarms are wired to a channel someone reads.
6. **Only then**: set `confirm_irreversible_compliance_lock = true` and switch
   `lock.mode` to `"compliance"`.

Step 5 is the one that gets skipped under deadline pressure, and step 6 is the one that
cannot be undone. That ordering is the reason the module defaults to governance mode
and requires an explicit acknowledgement to leave it.
