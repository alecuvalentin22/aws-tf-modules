###############################################################################
# Restore testing
#
# The control that separates a backup policy from a backup hypothesis.
#
# AWS Backup restore testing picks a real recovery point inside a lookback
# window, restores it, records whether the restore succeeded and how long it
# took, then deletes the restored resource. The result is evidence -- an RTO
# measurement and a pass/fail per resource type -- rather than an assertion.
#
# Neither Vault Lock nor cross-account copy tells you whether the data can be
# read back. Only this does. It is also what turns "we meet our RTO" from a
# design claim into a number someone can put in front of an auditor.
###############################################################################

locals {
  # Test what we actually depend on: the primary vault and every managed copy
  # destination. A copy that has never been restored from is an assumption, not
  # a second line of defence.
  restore_testing_include_vaults = concat(
    [module.primary_vault.arn],
    [for k, m in module.copy_vault : m.arn],
  )
}

resource "aws_backup_restore_testing_plan" "this" {
  count = var.enable_restore_testing ? 1 : 0

  region = local.primary_region

  # The API rejects hyphens in this name.
  name                         = replace("${var.name}_restore_test", "-", "_")
  schedule_expression          = var.restore_testing.schedule
  schedule_expression_timezone = var.restore_testing.schedule_timezone
  start_window_hours           = var.restore_testing.start_window_hours

  recovery_point_selection {
    algorithm = "LATEST_WITHIN_WINDOW"

    include_vaults = local.restore_testing_include_vaults

    recovery_point_types  = var.restore_testing.recovery_point_types
    selection_window_days = var.restore_testing.selection_window_days
  }

  tags = local.tags
}

resource "aws_backup_restore_testing_selection" "this" {
  for_each = var.enable_restore_testing ? toset(var.restore_testing.resource_types) : toset([])

  region = local.primary_region

  name                      = replace("${var.name}_${lower(each.key)}", "-", "_")
  restore_testing_plan_name = aws_backup_restore_testing_plan.this[0].name
  protected_resource_type   = each.key
  iam_role_arn              = local.restore_testing_role_arn

  # Restore only from recovery points this plan produced, so a test failure is
  # attributable to this plan rather than to someone else's.
  protected_resource_conditions {
    string_equals {
      key   = "aws:ResourceTag/BackupRule"
      value = var.rules[0].name
    }
  }

  validation_window_hours = var.restore_testing.validation_window_hours
}
