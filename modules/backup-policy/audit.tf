###############################################################################
# Audit Manager framework
#
# Each control below corresponds to one requirement this module implements. The
# point is to close the loop: the module configures the control, and the
# framework independently evaluates whether the control is actually in effect
# across the estate. Findings flow into AWS Config and from there into Security
# Hub, so a resource that drifts out of compliance surfaces without anyone
# re-reading the Terraform.
#
# Requires AWS Config to be recording in this account and Region. Without it the
# framework deploys and reports nothing, which is worse than not deploying it,
# so it is guarded by a variable rather than always on.
###############################################################################

resource "aws_backup_framework" "this" {
  count = var.enable_audit_framework ? 1 : 0

  region = local.primary_region

  name        = replace("${var.name}_framework", "-", "_")
  description = "Continuously evaluated controls for the ${var.name} backup policy"
  tags        = local.tags

  # SELECTION: every resource carrying the mandated tags is covered by a plan.
  # This is the control that catches the gap between "the plan exists" and "the
  # plan protects what it is supposed to".
  control {
    name = "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"

    scope {
      tags = var.selection_required_tags
    }
  }

  # FREQUENCY and RETENTION: plans run at least as often, and keep at least as
  # long, as policy requires.
  control {
    name = "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"

    input_parameter {
      name  = "requiredFrequencyUnit"
      value = "days"
    }

    input_parameter {
      name  = "requiredFrequencyValue"
      value = "1"
    }

    input_parameter {
      name  = "requiredRetentionDays"
      value = tostring(min([for r in var.rules : r.retention.delete_after]...))
    }
  }

  # RETENTION, evaluated on the recovery points themselves rather than the plan.
  control {
    name = "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"

    input_parameter {
      name  = "requiredRetentionDays"
      value = tostring(min([for r in var.rules : r.retention.delete_after]...))
    }
  }

  # ENCRYPTION.
  control {
    name = "BACKUP_RECOVERY_POINT_ENCRYPTED"
  }

  # WORM.
  control {
    name = "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
  }

  # CROSS-REGION COPY.
  dynamic "control" {
    for_each = length(local.managed_destinations) > 0 ? [1] : []

    content {
      name = "BACKUP_RESOURCES_PROTECTED_BY_CROSS_REGION"
    }
  }

  # CROSS-ACCOUNT COPY.
  dynamic "control" {
    for_each = length(local.external_destinations) > 0 ? [1] : []

    content {
      name = "BACKUP_RESOURCES_PROTECTED_BY_CROSS_ACCOUNT"
    }
  }

  # RESTORE TESTING: restores are not only configured but actually succeeding.
  dynamic "control" {
    for_each = var.enable_restore_testing ? [1] : []

    content {
      name = "RESTORE_TIME_FOR_RESOURCES_MEET_TARGET"

      input_parameter {
        name  = "maxRestoreTime"
        value = "720"
      }
    }
  }
}

###############################################################################
# Reports
#
# Job, copy and restore reports land in S3 as evidence. Restore-job reports are
# the ones an auditor asks for and the ones nobody has.
###############################################################################

locals {
  report_templates = var.enable_audit_reports ? merge(
    {
      backup_jobs = "BACKUP_JOB_REPORT"
      copy_jobs   = "COPY_JOB_REPORT"
    },
    var.enable_restore_testing ? { restore_jobs = "RESTORE_JOB_REPORT" } : {},
  ) : {}
}

resource "aws_backup_report_plan" "this" {
  for_each = local.report_templates

  region = local.primary_region

  name        = replace("${var.name}_${each.key}", "-", "_")
  description = "Daily ${each.value} for the ${var.name} backup policy"
  tags        = local.tags

  report_delivery_channel {
    s3_bucket_name = var.report_bucket_name
    formats        = ["CSV", "JSON"]
  }

  report_setting {
    report_template = each.value
  }
}
