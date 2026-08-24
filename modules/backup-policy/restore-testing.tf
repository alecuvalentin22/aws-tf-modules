# One plan per Region, not one plan listing every vault. Restore testing is
# regional: a plan in eu-central-1 cannot select recovery points from a vault in
# eu-west-1, so a single plan naming all of them tests the local vault and skips
# the copies.


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

  # Some protected resource types contain spaces ("SAP HANA on Amazon EC2"), and
  # the API accepts only alphanumerics and underscores. Replacing hyphens alone
  # leaves those rejected at apply time.
  name                      = replace(lower("${var.name}_${each.value.resource_type}"), "/[^a-z0-9]+/", "_")
  restore_testing_plan_name = aws_backup_restore_testing_plan.this[each.value.region].name
  protected_resource_type   = each.value.resource_type
  iam_role_arn              = local.restore_testing_role_arn

  # Note this is necessarily WIDER than the backup selection:
  # protected_resource_conditions supports only string_equals/string_not_equals,
  # so the Owner PATTERN (selection_required_tag_patterns) cannot be expressed
  # here. Harmless, a resource the plan never selected has no recovery points
  # to restore, but it is why the two conditions are not identical.
  #
  # protected_resource_conditions filters the PROTECTED RESOURCE by its own
  # tags, the source volume, instance or table, not the recovery point. So
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
