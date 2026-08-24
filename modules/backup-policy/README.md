# `backup-policy`

A reusable AWS Backup module: a tiered backup plan, tag-driven resource selection,
cross-Region and cross-account copies, WORM-protected vaults, failure alerting,
scheduled restore testing and continuously evaluated audit controls.

Design rationale is in [`docs/scenario-4-backup-policy.md`](../../docs/scenario-4-backup-policy.md)
and the [ADRs](../../docs/adr). This file is usage.

---

## Quick start

```hcl
module "backup_policy" {
  source = "./modules/backup-policy"

  name = "platform-backup"

  copy_destinations = {
    secondary_region = { region = "eu-west-1" }
  }

  rules = [{
    name      = "daily"
    schedule  = "cron(0 2 * * ? *)"
    retention = { delete_after = 35 }
    copy_to   = ["secondary_region"]
  }]

  selection_required_tags         = { ToBackup = "true" }
  selection_required_tag_patterns = { Owner = "*@example.com" }
}
```

Runnable configurations: [`examples/minimal`](examples/minimal) (one account, two
Regions) and [`examples/complete`](examples/complete) (the full two-account topology).

---

## What it creates

```
                    +--------------------------------------+
                    |  backup plan  (primary Region)       |
                    |  daily / weekly / monthly            |
                    +---------------+----------------------+
                                    |  selection: ToBackup=true AND Owner=*
                                    v
                    +--------------------------------------+
                    |  primary vault  + CMK + Vault Lock   |
                    +-------+----------------------+-------+
                            | copy_action          | copy_action
                            v                      v
        +---------------------------+   +----------------------------+
        | managed destination(s)    |   | external destination       |
        | any Region, same account  |   | another ACCOUNT            |
        | own CMK + Vault Lock      |   | deployed via backup-vault, |
        | created by this module    |   | referenced by ARN          |
        +---------------------------+   +----------------------------+

  plus: service role - SNS + EventBridge on failures - failure and staleness alarms
        - restore testing plan - Audit Manager framework - optional report plans
```

Managed destinations set `region`; the module builds the vault, its key and its
lock. **External** destinations set `vault_arn`; the module only references them. That
split exists because a different account needs different credentials, see
[ADR-0004](../../docs/adr/0004-module-composition-and-account-boundaries.md).

---

## Requirements

| | |
| --- | --- |
| Terraform | `>= 1.9.0` |
| AWS provider | `>= 6.0.0, < 7.0.0` - v6 is required for the per-resource `region` argument |

---

## Key inputs

Full descriptions are on each variable in [`variables.tf`](variables.tf).

### `rules` - frequency, retention, and where copies go

```hcl
rules = [
  {
    name      = "daily"
    schedule  = "cron(0 2 * * ? *)"        # frequency
    retention = { delete_after = 35 }       # retention
    copy_to   = ["secondary_region"]
  },
  {
    name      = "monthly"
    schedule  = "cron(0 4 1 * ? *)"
    retention = { delete_after = 2555, cold_storage_after = 90 }
    copy_to   = ["secondary_region", "backup_account"]

    # Per-destination override; anything unnamed inherits `retention`.
    copy_retention = {
      secondary_region = { delete_after = 365 }
      backup_account   = { delete_after = 2555, cold_storage_after = 90 }
    }
  },
]
```

> **A copy action inherits its rule's schedule.** AWS Backup has no independent copy
> frequency, so a different copy cadence is a different rule. That is why `copy_to` is
> per-rule: the daily tier can stay in-account while the weekly and monthly tiers pay
> for an account boundary.

### `copy_destinations`

```hcl
copy_destinations = {
  # Managed: this module creates the vault, its key and its lock.
  secondary_region = {
    region = "eu-west-1"
    lock   = { enabled = true, mode = "governance", min_retention_days = 7, max_retention_days = 3650 }
  }

  # External: owned by another account and referenced by ARN.
  backup_account = {
    vault_arn = module.backup_account_vault.arn

    # Declaring the destination's lock window lets the module reject, at plan time, a
    # retention that AWS would reject nightly at run time. Omitting it is an ERROR
    # unless acknowledge_unchecked_copy_destinations is set: a guardrail that fails
    # open on the cross-account hop with no signal is worse than no guardrail.
    lock_min_retention_days = 7
    lock_max_retention_days = 3650

    # Required. The destination key policy granting arn:aws:iam::<this account>:root
    # only DELEGATES to this account's IAM. It authorises nothing by itself. The
    # backup role needs a matching IAM allow naming this key, or every encrypted
    # cross-account copy fails with AccessDenied.
    kms_key_arn_external = module.backup_account_vault.kms_key_arn
  }
}
```

### Selection - AND, not OR

```hcl
selection_required_tags         = { ToBackup = "true" }      # string_equals
selection_required_tag_patterns = { Owner = "*@example.com" } # string_like
selection_excluded_tag_patterns = { Environment = "sandbox*" } # string_not_like
```

All AND-ed. The module deliberately does **not** use `selection_tag`, whose multiple
blocks are OR-ed, see [ADR-0002](../../docs/adr/0002-condition-not-selection-tag.md).
An empty `selection_required_tags` is rejected.

`selection_required_tag_patterns` defaults to `{ Owner = "*@*" }` rather than empty: the
requirement is `ToBackup=true` **AND** an owner, and a default satisfying only half of it
reproduces the gap this module exists to prevent.

---

## What it refuses to do

Every one of these fails at `terraform plan`, with a message naming the offending rule
or destination, and every one has a test proving it fires.

| Refused | Because |
| --- | --- |
| A `delete_after` outside a destination's Vault Lock window | AWS enforces the window **at job time**. The apply succeeds and the job then fails nightly, in production |
| `delete_after < cold_storage_after + 90` | The archive tier has a 90-day minimum charge; AWS rejects the lifecycle |
| Continuous backup with `delete_after > 35` or cold storage | PITR is capped at 35 days and cannot be tiered |
| Archive opt-in without `cold_storage_after` | Silently does nothing otherwise |
| `copy_to` naming an undefined destination | A typo would otherwise produce a plan with a missing copy |
| `copy_retention` for a destination not in `copy_to` | Silently ignored otherwise |
| An empty `selection_required_tags` | `resources = ["*"]` with no condition backs up the whole account |
| An external destination with no declared lock window | Its retention cannot be checked; failing open on the cross-account hop, with no signal, defeats the guardrail. Waivable with `acknowledge_unchecked_copy_destinations`, and reported either way |
| An external destination with no `kms_key_arn_external` | The backup role could not be granted the destination key, so every encrypted copy would fail with AccessDenied. **Not** waivable - it is a different failure from the one above, and a shared escape hatch would let an unlocked sandbox Region switch this off too |
| A field that applies only to the other kind of destination | A setting that appears to take effect and does not is worse than one that is refused |
| `disable_cold_storage` together with `cold_storage_after` | Contradictory |
| `vault_force_destroy` with a deny-delete policy that exempts nobody | `destroy` would fail with AccessDenied and nothing would say which setting caused it |
| `completion_window_minutes == start_window_minutes` | AWS requires it to be strictly greater |
| Continuous backup with copies, unacknowledged | Copying continuous recovery points is only supported for some resource types |
| A destination that is both `region` and `vault_arn`, or neither | Ambiguous |
| A COMPLIANCE lock without `confirm_irreversible_compliance_lock` | It cannot be undone by anyone, including AWS |

---

## Vault Lock

Governance is the default. Compliance mode is the target state, but it is
irreversible, so the module requires an explicit acknowledgement:

```hcl
primary_vault = {
  lock = { enabled = true, mode = "compliance", min_retention_days = 35, max_retention_days = 3650 }
}
confirm_irreversible_compliance_lock = true
```

Do this only after a full backup -> copy -> **restore** cycle has been proven in
governance mode. Once the grace period elapses: retention cannot be shortened, recovery
points cannot be deleted early, `terraform destroy` fails while the vault holds
recovery points, and no principal can undo it, including the account root and AWS
Support. [ADR-0001](../../docs/adr/0001-vault-lock-compliance-mode.md).

---

## Two singletons this module will not touch by default

| Variable | Default | Why |
| --- | --- | --- |
| `opt_in_resource_types` | `null` | `aws_backup_region_settings` is an account-and-Region singleton. Two states managing it will revert each other on every apply. Own it once in the account baseline. **But note**: `resources = ["*"]` only covers types that are opted in - an un-opted type is skipped with no error and no warning |
| `enable_cross_account_backup_global_setting` | `false` | `aws_backup_global_settings` is an organisation singleton and is only valid from the Organizations management account. Cross-account copy does not work until it is on |

---

## Operational notes

- **Notifications** are per Region - a vault cannot publish to a topic in another
  Region, so the module creates one SNS topic per Region it places a vault in.
  `notification_subscriptions` subscribes to the primary-Region topic.
- **The staleness alarm uses `treat_missing_data = "breaching"`.** A plan that stops
  running emits no failure metric at all, so absence of data *is* the failure. This is
  the only alarm that catches a deleted selection or a revoked role.
- **`effective_copy_matrix`** outputs which tier copies where with what retention at
  each hop. Worth pasting into a change record; the copy topology is the part of a
  backup policy most often misread from the Terraform.
- **`terraform destroy`** will fail against a compliance-locked vault holding recovery
  points. That is the lock doing its job.

---

## Testing

```bash
cd modules/backup-policy && terraform init && terraform test                       # 64 tests
cd modules/backup-policy/modules/backup-vault && terraform init && terraform test  # 20 tests
```

All 84 run against a **mocked provider**: no AWS account, no credentials, so they work
as a required CI check. Shared mocks live in `tests/mocks/aws.tfmock.hcl`.

| File | Covers |
| --- | --- |
| `tests/defaults.tftest.hcl` | Shipped behaviour: tiers, copy topology, AND-semantics selection, one key per vault, restore-testing scope, alarm semantics |
| `tests/guardrails.tftest.hcl` | Every configuration the module refuses, plus the accept case for the lock window |
| `tests/scaling.tftest.hcl` | Five destinations across five Regions and one cross-account target |
| `tests/policies.tftest.hcl` | The rendered trust, copy/encrypt, SNS key and topic policies - the full cross-account permission path |
| `tests/audit.tftest.hcl` | Framework controls, and that its parameters follow the configuration rather than constants |
| `modules/backup-vault/tests/lock.tftest.hcl` | Lock modes and the compliance acknowledgement guard |
| `modules/backup-vault/tests/policies.tftest.hcl` | The rendered vault and KMS key policies, including the scoping of the cross-account grant |

Policies are built with `jsonencode` rather than `aws_iam_policy_document` specifically
so this is possible: a mocked provider cannot compute a data source, so a policy built
that way renders as an empty placeholder and every statement in it goes untested. These
policies decide whether a copy job succeeds or fails with `AccessDenied` at 02:00.

---

## Submodule

[`modules/backup-vault`](modules/backup-vault) - one vault, its CMK and key policy, its
Vault Lock, its deny-delete access policy and its notifications. Used by this module for
the primary and managed destinations, and deployed **standalone in the backup account**
to create the cross-account destination:

```hcl
module "backup_account_vault" {
  source    = "./modules/backup-policy/modules/backup-vault"
  providers = { aws = aws.backup_account }

  name               = "platform-backup-isolated"
  source_account_ids = ["111111111111"]   # the prod account, granted on BOTH the
                                          # vault policy and the KMS key policy
  lock = { enabled = true, mode = "governance", min_retention_days = 7, max_retention_days = 3650 }
}
```

Pass its `arn` **and** its `kms_key_arn` back to `backup-policy` as an external
destination. The cross-account permission path is four grants and all four are
required:

| # | Grant | Where |
| --- | --- | --- |
| 1 | source role -> `backup:CopyIntoBackupVault` on the destination vault | `backup-policy` |
| 2 | source role -> KMS data plane on the destination **key** | `backup-policy` |
| 3 | destination vault policy -> the source account | `backup-vault` |
| 4 | destination key policy -> the source account | `backup-vault` |

Grant 2 is the one that gets missed, because grant 4 looks sufficient, but a key
policy naming `<account>:root` only *delegates* to that account's IAM; it authorises
nothing on its own. That is why `kms_key_arn_external` is required rather than optional.
