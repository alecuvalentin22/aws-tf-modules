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
  # referenced. They are deployed separately, with their own credentials.
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
  # Destinations that do not exist are filtered out here rather than indexed
  # into. Indexing would fail first, with Terraform's generic "Invalid index"
  # pointing at this file, instead of the plan precondition below naming the
  # rule and the typo.
  copy_actions = {
    for r in var.rules : r.name => [
      for dest in r.copy_to : {
        destination           = dest
        destination_vault_arn = local.destination_vault_arns[dest]
        # Merge field by field, don't substitute wholesale. `{ delete_after = 2555 }`
        # on a rule that sets cold_storage_after would otherwise give a 7-year copy
        # sitting in warm storage, with nothing in the plan to show it.
        #
        # The copy_retention object attributes are `optional` with no default, so
        # an unset field is null and stays distinguishable from an explicit false.
        lifecycle_config = {
          delete_after = coalesce(
            try(r.copy_retention[dest].delete_after, null),
            r.retention.delete_after,
          )
          cold_storage_after = try(r.copy_retention[dest].disable_cold_storage, false) ? null : (
            try(r.copy_retention[dest].cold_storage_after, null) != null
            ? r.copy_retention[dest].cold_storage_after
            : r.retention.cold_storage_after
          )
          opt_in_to_archive_for_supported_resources = try(r.copy_retention[dest].opt_in_to_archive_for_supported_resources, null) != null ? (
            r.copy_retention[dest].opt_in_to_archive_for_supported_resources
          ) : r.retention.opt_in_to_archive_for_supported_resources
        }
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
  primary_lock_window = {
    enabled = var.primary_vault.lock.enabled
    min     = var.primary_vault.lock.min_retention_days
    max     = var.primary_vault.lock.max_retention_days
  }

  # Keyed only by destination name. The primary vault's window is deliberately
  # NOT merged into this map under a sentinel key: a destination named after the
  # sentinel would then overwrite it, and the primary vault's retention check
  # would pass for any value. A guardrail that fails open on a name
  # collision is worse than no guardrail.
  destination_lock_windows = merge(
    {
      for k, d in local.managed_destinations : k => {
        enabled = d.lock.enabled
        min     = d.lock.min_retention_days
        max     = d.lock.max_retention_days
      }
    },
    {
      for k, d in local.external_destinations : k => {
        # Only checkable when the caller declares the external vault's window --
        # this module cannot read a Vault Lock in another account.
        enabled = d.lock_min_retention_days != null || d.lock_max_retention_days != null
        min     = coalesce(d.lock_min_retention_days, 1)
        max     = coalesce(d.lock_max_retention_days, 36500)
      }
    },
  )

  # Two different things are easily conflated, and only one of them is a problem:
  #
  #   Deliberately not locked:  lock.enabled = false on a vault this module can
  #                               see. There is no window to check because the
  #                               operator said so. A stated intent, not a gap.
  #   Window not declared:      an EXTERNAL destination whose Vault Lock lives in
  #                               another account, which this module cannot read.
  #                               Its retention is genuinely unvalidated.
  #
  # Only the second requires acknowledgement. Making the first require it too
  # meant an ordinary sandbox, one unlocked copy Region, forced the
  # acknowledgement flag on, and that flag then waived unrelated checks.
  unchecked_destinations = sort([
    for k, d in local.external_destinations : k
    if d.lock_min_retention_days == null && d.lock_max_retention_days == null
  ])

  # Everything whose retention was not validated, for whatever reason, so the
  # omission is visible rather than silent. Reported even when acknowledged, and
  # symmetric across the primary vault and the copy destinations, the vault
  # every job writes to first should not be the one checked least.
  unvalidated_retention_targets = sort(concat(
    local.primary_lock_window.enabled ? [] : ["primary vault (lock disabled)"],
    [
      for k, w in local.destination_lock_windows : "${k} (lock disabled)"
      if !w.enabled && contains(keys(local.managed_destinations), k)
    ],
    [
      for k in local.unchecked_destinations : "${k} (external, lock window not declared)"
    ],
  ))

  # External destinations whose KMS key ARN was not supplied. Only material when
  # this module builds the backup role, a caller supplying their own role owns
  # its permissions.
  external_destinations_missing_key = var.backup_role_arn != null ? [] : sort([
    for k, d in local.external_destinations : k if d.kms_key_arn_external == null
  ])

  primary_retention_violations = [
    for r in var.rules : format(
      "rule %q -> primary vault: delete_after=%d is outside the vault lock window [%d, %d]",
      r.name,
      r.retention.delete_after,
      local.primary_lock_window.min,
      local.primary_lock_window.max,
    )
    if local.primary_lock_window.enabled && (
      r.retention.delete_after < local.primary_lock_window.min ||
      r.retention.delete_after > local.primary_lock_window.max
    )
  ]

  copy_retention_violations = flatten([
    for r in var.rules : [
      for c in local.copy_actions[r.name] : format(
        "rule %q -> destination %q: delete_after=%d is outside the vault lock window [%d, %d]",
        r.name,
        c.destination,
        c.lifecycle_config.delete_after,
        local.destination_lock_windows[c.destination].min,
        local.destination_lock_windows[c.destination].max,
      )
      if local.destination_lock_windows[c.destination].enabled && (
        c.lifecycle_config.delete_after < local.destination_lock_windows[c.destination].min ||
        c.lifecycle_config.delete_after > local.destination_lock_windows[c.destination].max
      )
    ]
  ])

  retention_violations = concat(
    local.primary_retention_violations,
    local.copy_retention_violations,
  )

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

  # Keys the backup role needs IAM permission on. A destination key policy that
  # grants `<source-account>:root` only DELEGATES to that account's IAM. It
  # does not itself authorise any principal there. Both sides must allow, so an
  # external destination's key ARN has to be named here too or every encrypted
  # cross-account copy fails with AccessDenied on the destination key.
  external_destination_key_arns = compact([
    for k, d in local.external_destinations : d.kms_key_arn_external
  ])

  backup_role_arn = var.backup_role_arn != null ? var.backup_role_arn : aws_iam_role.backup[0].arn

  restore_testing_role_arn = coalesce(var.restore_testing_iam_role_arn, local.backup_role_arn)

  create_notifications = var.enable_notifications

  # ---------------------------------------------------------------------------
  # Audit framework inputs, derived from the configuration rather than hardcoded.
  # ---------------------------------------------------------------------------
  shortest_retention_days = min([for r in var.rules : r.retention.delete_after]...)

  # How many days may pass between backups, taken from the LEAST frequent rule.
  #
  # AWS cron has six fields: minute hour day-of-month month day-of-week year.
  # A pinned day-of-month means monthly; a pinned day-of-week means weekly;
  # anything else is treated as daily. Deliberately coarse, the Audit Manager
  # parameter is in whole days, so a full cron parser would add risk without
  # adding resolution.
  cron_fields = {
    for r in var.rules : r.name => (
      startswith(r.schedule, "cron(")
      ? split(" ", trimsuffix(trimprefix(r.schedule, "cron("), ")"))
      : []
    )
  }

  # rate(N unit) is the other accepted form. Ignoring it and defaulting to 1 day
  # reproduces exactly the false positive this derivation exists to remove: a
  # fortnightly plan reported non-compliant against a daily requirement, forever.
  rate_parts = {
    for r in var.rules : r.name => (
      startswith(r.schedule, "rate(")
      ? split(" ", trimsuffix(trimprefix(r.schedule, "rate("), ")"))
      : []
    )
  }

  rule_gap_days = [
    for r in var.rules : (
      length(local.rate_parts[r.name]) == 2 ? (
        # Sub-daily rates still mean "at least daily" for a control measured in
        # whole days.
        startswith(local.rate_parts[r.name][1], "day") ? tonumber(local.rate_parts[r.name][0]) : 1
        ) : (
        length(local.cron_fields[r.name]) < 5 ? 1 :
        !contains(["*", "?"], local.cron_fields[r.name][2]) ? 31 :
        !contains(["*", "?"], local.cron_fields[r.name][4]) ? 7 : 1
      )
    )
  ]

  # MIN, not max.
  #
  # BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK passes when a plan has at
  # least one rule meeting the requirement. Parameterising it with the LEAST
  # frequent tier (max) would let the plan pass on its monthly rule alone, so the
  # control could not detect the daily tier being deleted. The tightest configured
  # cadence is the assertion worth making: the plan still runs as often as it was
  # written to.
  required_frequency_days = min(local.rule_gap_days...)

  copy_destination_regions = distinct([
    for k, d in local.managed_destinations : coalesce(d.region, local.primary_region)
  ])

  external_destination_account_ids = distinct(compact([
    for k, d in local.external_destinations :
    try(split(":", d.vault_arn)[4], null)
  ]))

  # Null when the selection carries more or fewer than one exact-match tag: the
  # AWS ControlScope API accepts at most one, so there is no correct way to
  # render two.
  audit_scope_tag = (
    var.audit_scope_tag != null ? var.audit_scope_tag :
    length(var.selection_required_tags) == 1 ? var.selection_required_tags : null
  )
}
