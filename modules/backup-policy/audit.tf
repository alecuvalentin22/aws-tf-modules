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

  # SELECTION: every resource carrying the mandated tag is covered by a plan.
  # This is the control that catches the gap between "the plan exists" and "the
  # plan protects what it is supposed to".
  #
  # The scope carries at most ONE tag: that is the AWS ControlScope limit, not a
  # simplification. It also cannot express the pattern-matched tags, so the
  # framework's scope is necessarily WIDER than the plan's selection -- a
  # resource tagged ToBackup=true but with no Owner is deliberately excluded from
  # the plan and will be reported here as unprotected. That finding is correct:
  # the resource needs an owner. See the audit_scope_tag variable.
  control {
    name = "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN"

    dynamic "scope" {
      for_each = local.audit_scope_tag == null ? [] : [local.audit_scope_tag]

      content {
        tags = scope.value
      }
    }
  }

  # FREQUENCY and RETENTION: plans run at least as often, and keep at least as
  # long, as policy requires.
  #
  # Both parameters are derived from the configured rules. Hardcoding a daily
  # frequency would report a plan whose shortest tier is weekly as permanently
  # non-compliant -- a standing false positive that teaches the operator to
  # ignore the framework, which is worse than not deploying it.
  control {
    name = "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"

    input_parameter {
      name  = "requiredFrequencyUnit"
      value = "days"
    }

    input_parameter {
      name  = "requiredFrequencyValue"
      value = tostring(local.required_frequency_days)
    }

    input_parameter {
      name  = "requiredRetentionDays"
      value = tostring(local.shortest_retention_days)
    }
  }

  # RETENTION, evaluated on the recovery points themselves rather than the plan.
  control {
    name = "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"

    input_parameter {
      name  = "requiredRetentionDays"
      value = tostring(local.shortest_retention_days)
    }
  }

  # ENCRYPTION.
  control {
    name = "BACKUP_RECOVERY_POINT_ENCRYPTED"
  }

  # Scoped for the same reason as the coverage control above: unscoped, these
  # evaluate every supported resource in the account, so any account holding
  # resources deliberately not backed up produces a large standing volume of
  # non-compliance that buries the real findings.
  #
  # WORM. Both controls, because they check different things and the module's
  # whole thesis is that only the first of them is load-bearing:
  #   ..._BACKUP_VAULT_LOCK      evaluates Vault Lock itself
  #   ..._MANUAL_DELETION_DISABLED  evaluates the vault ACCESS POLICY, which an
  #                                 administrator can remove
  # Auditing only the second would be auditing the weaker control.
  control {
    name = "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_VAULT_LOCK"

    dynamic "scope" {
      for_each = local.audit_scope_tag == null ? [] : [local.audit_scope_tag]

      content {
        tags = scope.value
      }
    }
  }

  control {
    name = "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
  }

  # CROSS-REGION COPY. Pinned to the Regions this module actually copies to.
  # Without the parameter the control passes for a copy to ANY Region, including
  # one nobody intended -- which makes it a check that the feature is on rather
  # than a check that the policy is met.
  dynamic "control" {
    for_each = length(local.managed_destinations) > 0 ? [1] : []

    content {
      name = "BACKUP_RESOURCES_PROTECTED_BY_CROSS_REGION"

      dynamic "scope" {
        for_each = local.audit_scope_tag == null ? [] : [local.audit_scope_tag]

        content {
          tags = scope.value
        }
      }

      input_parameter {
        name  = "crossRegionList"
        value = join(",", local.copy_destination_regions)
      }
    }
  }

  # CROSS-ACCOUNT COPY. Pinned to the destination accounts, for the same reason.
  dynamic "control" {
    for_each = length(local.external_destination_account_ids) > 0 ? [1] : []

    content {
      name = "BACKUP_RESOURCES_PROTECTED_BY_CROSS_ACCOUNT"

      dynamic "scope" {
        for_each = local.audit_scope_tag == null ? [] : [local.audit_scope_tag]

        content {
          tags = scope.value
        }
      }

      input_parameter {
        name  = "crossAccountList"
        value = join(",", local.external_destination_account_ids)
      }
    }
  }

  # RESTORE TESTING: restores are not only configured but actually succeeding.
  dynamic "control" {
    for_each = var.enable_restore_testing ? [1] : []

    content {
      name = "RESTORE_TIME_FOR_RESOURCES_MEET_TARGET"

      input_parameter {
        name = "maxRestoreTime"
        # MINUTES, not hours. The default is 12 hours; a reader who assumes
        # hours here would be setting a 30-day RTO target.
        value = tostring(var.restore_time_target_minutes)
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
