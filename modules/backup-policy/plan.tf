###############################################################################
# The plan
#
# One rule per tier. A rule carries the frequency (schedule), the retention
# (lifecycle) and the encryption (implicitly, via the vault's KMS key), and fans
# out to its copy destinations.
#
# AWS Backup has no independent copy frequency: a copy_action inherits the
# schedule of the rule that owns it. "Cross-Region copy with a defined frequency"
# is therefore expressed as which rules carry which copy actions -- the default
# copies dailies cross-Region only, and sends weeklies and monthlies to the
# isolated account too.
###############################################################################

resource "aws_backup_plan" "this" {
  region = local.primary_region

  name = var.name
  tags = local.tags

  dynamic "rule" {
    for_each = { for r in var.rules : r.name => r }

    content {
      rule_name         = rule.value.name
      target_vault_name = module.primary_vault.name

      schedule                     = rule.value.schedule
      schedule_expression_timezone = rule.value.schedule_timezone
      start_window                 = rule.value.start_window_minutes
      completion_window            = rule.value.completion_window_minutes
      enable_continuous_backup     = rule.value.enable_continuous_backup

      # Stamping the rule onto the recovery point is what makes it possible to
      # answer "which tier produced this?" during an incident, and to build
      # lifecycle reports per tier.
      recovery_point_tags = merge(
        local.tags,
        { BackupRule = rule.value.name },
        rule.value.recovery_point_tags,
      )

      lifecycle {
        delete_after                              = rule.value.retention.delete_after
        cold_storage_after                        = rule.value.retention.cold_storage_after
        opt_in_to_archive_for_supported_resources = rule.value.retention.opt_in_to_archive_for_supported_resources
      }

      dynamic "copy_action" {
        for_each = local.copy_actions[rule.value.name]

        content {
          destination_vault_arn = copy_action.value.destination_vault_arn

          lifecycle {
            delete_after                              = copy_action.value.lifecycle_config.delete_after
            cold_storage_after                        = copy_action.value.lifecycle_config.cold_storage_after
            opt_in_to_archive_for_supported_resources = copy_action.value.lifecycle_config.opt_in_to_archive_for_supported_resources
          }
        }
      }
    }
  }

  lifecycle {
    # Checks that cannot be expressed as variable validations, because they span
    # more than one variable.
    precondition {
      condition     = length(local.unknown_copy_targets) == 0
      error_message = "rules[*].copy_to names destinations that are not defined in copy_destinations: ${join("; ", local.unknown_copy_targets)}."
    }

    precondition {
      condition     = length(local.retention_violations) == 0
      error_message = <<-EOT
        Backup retention falls outside a Vault Lock retention window.

        AWS Backup enforces a vault's min/max retention on every incoming backup and copy job.
        Applying this plan would succeed, and then every affected job would fail nightly.

        ${join("\n        ", local.retention_violations)}

        Fix by widening the vault lock window or changing the rule's delete_after. Note that a
        COMPLIANCE lock's window cannot be widened after its grace period ends.
      EOT
    }

    precondition {
      condition     = !var.enable_audit_reports || var.report_bucket_name != null
      error_message = "report_bucket_name is required when enable_audit_reports is true."
    }
  }
}

###############################################################################
# Selection
#
# `resources = ["*"]` scopes to every opted-in resource type; the condition block
# narrows it to resources carrying all the mandated tags.
#
# `condition` rather than `selection_tag` is deliberate and is the correctness
# crux of the module: AWS Backup evaluates multiple selection_tag blocks with OR,
# so a resource tagged ToBackup=true and nothing else would be selected even
# though the policy requires an owner too. condition entries are AND-ed.
###############################################################################

resource "aws_backup_selection" "this" {
  region = local.primary_region

  name         = "${var.name}-tagged"
  plan_id      = aws_backup_plan.this.id
  iam_role_arn = local.backup_role_arn

  resources     = var.selection_resources
  not_resources = var.selection_not_resources

  condition {
    dynamic "string_equals" {
      for_each = local.selection_string_equals

      content {
        key   = string_equals.key
        value = string_equals.value
      }
    }

    dynamic "string_like" {
      for_each = local.selection_string_like

      content {
        key   = string_like.key
        value = string_like.value
      }
    }

    dynamic "string_not_like" {
      for_each = local.selection_string_not_like

      content {
        key   = string_not_like.key
        value = string_not_like.value
      }
    }
  }
}
