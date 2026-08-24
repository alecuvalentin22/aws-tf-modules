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
# read back. Only this does.
#
# One plan PER REGION, not one plan listing every vault. Restore testing is a
# regional service: a plan in eu-central-1 cannot select recovery points from a
# vault in eu-west-1. A single plan naming all of them would test only the local
# vault and quietly skip the copies -- which is precisely the assumption this is
# supposed to disprove.
###############################################################################

locals {
  # Vaults grouped by the Region they live in, so each Region's testing plan
  # selects only vaults it can actually reach.
  vaults_by_region = {
    for r in local.managed_regions : r => concat(
      r == local.primary_region ? [module.primary_vault.arn] : [],
      [
        for k, d in local.managed_destinations :
        module.copy_vault[k].arn
        if coalesce(d.region, local.primary_region) == r
      ],
    )
  }

  restore_testing_regions = var.enable_restore_testing ? local.managed_regions : []

  # Every (Region, resource type) pair needs its own testing selection.
  restore_testing_selections = {
    for pair in setproduct(local.restore_testing_regions, var.restore_testing.resource_types) :
    "${pair[0]}-${lower(pair[1])}" => {
      region        = pair[0]
      resource_type = pair[1]
    }
  }
}

resource "aws_backup_restore_testing_plan" "this" {
  for_each = toset(local.restore_testing_regions)

  region = each.key

  # The API rejects hyphens in this name.
  name                         = replace("${var.name}_restore_test_${each.key}", "-", "_")
  schedule_expression          = var.restore_testing.schedule
  schedule_expression_timezone = var.restore_testing.schedule_timezone
  start_window_hours           = var.restore_testing.start_window_hours

  recovery_point_selection {
    algorithm             = "LATEST_WITHIN_WINDOW"
    include_vaults        = local.vaults_by_region[each.key]
    recovery_point_types  = var.restore_testing.recovery_point_types
    selection_window_days = var.restore_testing.selection_window_days
  }

  tags = local.tags
}

resource "aws_backup_restore_testing_selection" "this" {
  for_each = local.restore_testing_selections

  region = each.value.region

  name                      = replace("${var.name}_${lower(each.value.resource_type)}", "-", "_")
  restore_testing_plan_name = aws_backup_restore_testing_plan.this[each.value.region].name
  protected_resource_type   = each.value.resource_type
  iam_role_arn              = local.restore_testing_role_arn

  # protected_resource_conditions filters the PROTECTED RESOURCE by its own
  # tags -- the source volume, instance or table -- not the recovery point. So
  # the tags used here must be the ones the selection matches on, which are on
  # the resource. A recovery-point tag such as BackupRule is never present on
  # the protected resource, and conditioning on one produces a selection that
  # matches nothing: the testing plan runs weekly, tests zero resources, reports
  # success, and manufactures audit evidence for a control that is not running.
  dynamic "protected_resource_conditions" {
    for_each = length(var.selection_required_tags) > 0 ? [1] : []

    content {
      dynamic "string_equals" {
        for_each = local.selection_string_equals

        content {
          key   = string_equals.key
          value = string_equals.value
        }
      }
    }
  }

  validation_window_hours = var.restore_testing.validation_window_hours
}
