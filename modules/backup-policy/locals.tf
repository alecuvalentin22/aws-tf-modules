data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  partition      = data.aws_partition.current.partition
  primary_region = coalesce(var.primary_vault.region, data.aws_region.current.region)

  tags = merge(
    {
      ManagedBy = "terraform"
      Module    = "backup-policy"
    },
    var.tags,
  )

  primary_vault_name = coalesce(var.primary_vault.name, "${var.name}-primary")

  # ---------------------------------------------------------------------------
  # Copy destinations, split by who owns them.
  #
  # Managed destinations get a vault built by the child module in this account,
  # in an arbitrary Region, via the provider's per-resource `region` argument.
  # External destinations (in practice, the isolated backup account) are only
  # referenced -- they are deployed separately with their own credentials.
  # ---------------------------------------------------------------------------
  managed_destinations = {
    for k, d in var.copy_destinations : k => d if d.vault_arn == null
  }

  external_destinations = {
    for k, d in var.copy_destinations : k => d if d.vault_arn != null
  }

  destination_vault_arns = merge(
    { for k, m in module.copy_vault : k => m.arn },
    { for k, d in local.external_destinations : k => d.vault_arn },
  )

  # Every Region this module places a vault in, deduplicated. Used to create one
  # SNS topic per Region, because vault notifications cannot cross a Region.
  managed_regions = distinct(concat(
    [local.primary_region],
    [for k, d in local.managed_destinations : coalesce(d.region, local.primary_region)],
  ))

  # ---------------------------------------------------------------------------
  # Copy actions, flattened per rule so one dynamic block emits them all.
  # A destination not named in copy_retention inherits the rule's own lifecycle.
  # ---------------------------------------------------------------------------
  # Destinations that do not exist are filtered out here rather than indexed
  # into. Indexing would fail first, with Terraform's generic "Invalid index"
  # pointing at this file, instead of the plan precondition below naming the
  # rule and the typo.
  copy_actions = {
    for r in var.rules : r.name => [
      for dest in r.copy_to : {
        destination           = dest
        destination_vault_arn = local.destination_vault_arns[dest]
        lifecycle_config = lookup(r.copy_retention, dest, {
          delete_after                              = r.retention.delete_after
          cold_storage_after                        = r.retention.cold_storage_after
          opt_in_to_archive_for_supported_resources = r.retention.opt_in_to_archive_for_supported_resources
        })
      }
      if contains(keys(var.copy_destinations), dest)
    ]
  }

  # ---------------------------------------------------------------------------
  # Vault Lock cross-check.
  #
  # AWS Backup enforces a vault's min/max retention window on every incoming job,
  # not at apply time. A plan whose retention falls outside the destination's
  # window therefore applies cleanly and then fails every night, in production,
  # long after anyone is watching the apply output. Computing the mismatch here
  # turns that into a plan-time error.
  #
  # Each entry is (rule, destination, retention, window) so the error message can
  # name the exact rule and destination rather than saying "something is wrong".
  # ---------------------------------------------------------------------------
  lock_windows = merge(
    {
      "__primary__" = {
        enabled = var.primary_vault.lock.enabled
        min     = var.primary_vault.lock.min_retention_days
        max     = var.primary_vault.lock.max_retention_days
      }
    },
    {
      for k, d in local.managed_destinations : k => {
        enabled = d.lock.enabled
        min     = d.lock.min_retention_days
        max     = d.lock.max_retention_days
      }
    },
    {
      for k, d in local.external_destinations : k => {
        # Only checkable when the caller tells us the external vault's window.
        enabled = d.lock_min_retention_days != null || d.lock_max_retention_days != null
        min     = coalesce(d.lock_min_retention_days, 1)
        max     = coalesce(d.lock_max_retention_days, 36500)
      }
    },
  )

  retention_checks = flatten([
    for r in var.rules : concat(
      [{
        rule         = r.name
        destination  = "__primary__"
        delete_after = r.retention.delete_after
      }],
      [
        for c in local.copy_actions[r.name] : {
          rule         = r.name
          destination  = c.destination
          delete_after = c.lifecycle_config.delete_after
        }
      ],
    )
  ])

  retention_violations = [
    for c in local.retention_checks : format(
      "rule %q -> %s: delete_after=%d is outside the vault lock window [%d, %d]",
      c.rule,
      c.destination == "__primary__" ? "primary vault" : "destination ${c.destination}",
      c.delete_after,
      local.lock_windows[c.destination].min,
      local.lock_windows[c.destination].max,
    )
    if local.lock_windows[c.destination].enabled && (
      c.delete_after < local.lock_windows[c.destination].min ||
      c.delete_after > local.lock_windows[c.destination].max
    )
  ]

  # ---------------------------------------------------------------------------
  # A copy_to entry that names no destination would otherwise fail deep inside a
  # lookup with an unhelpful message.
  # ---------------------------------------------------------------------------
  unknown_copy_targets = distinct(flatten([
    for r in var.rules : [
      for dest in r.copy_to : "rule ${r.name} -> ${dest}"
      if !contains(keys(var.copy_destinations), dest)
    ]
  ]))

  # ---------------------------------------------------------------------------
  # Selection conditions. Every entry is AND-ed by AWS Backup.
  # ---------------------------------------------------------------------------
  selection_string_equals = {
    for k, v in var.selection_required_tags : "aws:ResourceTag/${k}" => v
  }

  selection_string_like = {
    for k, v in var.selection_required_tag_patterns : "aws:ResourceTag/${k}" => v
  }

  selection_string_not_like = {
    for k, v in var.selection_excluded_tag_patterns : "aws:ResourceTag/${k}" => v
  }

  backup_role_arn = var.backup_role_arn != null ? var.backup_role_arn : aws_iam_role.backup[0].arn

  restore_testing_role_arn = coalesce(var.restore_testing_iam_role_arn, local.backup_role_arn)

  create_notifications = var.enable_notifications
}
