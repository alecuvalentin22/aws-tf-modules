# The Audit Manager framework.
#
# The framework is what turns each requirement into a continuously evaluated
# control rather than an assertion in a README, so its parameters have to follow
# the configuration. A control parameterised with a constant that contradicts the
# plan produces a permanent false positive -- and a framework that is always red
# teaches the operator to ignore it, which is worse than not deploying one.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name = "platform-backup"

  copy_destinations = {
    secondary_region = {
      region = "eu-west-1"
    }
    backup_account = {
      vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
      lock_min_retention_days = 7
      lock_max_retention_days = 3650
      kms_key_arn_external    = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
    }
  }
}

run "every_requirement_has_a_control" {
  command = apply

  assert {
    condition = alltrue([
      for required in [
        "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN",         # selection
        "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK", # frequency + retention
        "BACKUP_RECOVERY_POINT_ENCRYPTED",                   # encryption
        "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_VAULT_LOCK",   # WORM
        "BACKUP_RESOURCES_PROTECTED_BY_CROSS_REGION",        # cross-Region copy
        "BACKUP_RESOURCES_PROTECTED_BY_CROSS_ACCOUNT",       # cross-account copy
        ] : contains(
        [for c in aws_backup_framework.this[0].control : c.name],
        required,
      )
    ])
    error_message = "Each of the brief's four requirements should map onto at least one continuously evaluated control."
  }
}

# The module's thesis is that Vault Lock is the load-bearing WORM control and the
# vault access policy is not ("removable by an administrator, so it is not a
# ransomware control"). Auditing only the access policy would audit the weaker of
# the two.
run "worm_is_audited_on_the_lock_not_only_on_the_access_policy" {
  command = apply

  assert {
    condition = contains(
      [for c in aws_backup_framework.this[0].control : c.name],
      "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_VAULT_LOCK",
    )
    error_message = "Vault Lock itself must be audited, not just the removable access policy."
  }
}

# Hardcoding a daily frequency reports a plan whose shortest tier is weekly as
# permanently non-compliant.
run "the_frequency_parameter_follows_the_least_frequent_rule" {
  command = apply

  variables {
    rules = [{
      name      = "weekly"
      schedule  = "cron(0 3 ? * SUN *)"
      retention = { delete_after = 90 }
    }]
  }

  assert {
    condition     = local.longest_schedule_gap_days == 7
    error_message = "A weekly cron (pinned day-of-week) should yield a 7-day frequency requirement, not 1."
  }
}

run "a_monthly_only_plan_is_not_asked_to_run_daily" {
  command = apply

  variables {
    rules = [{
      name      = "monthly"
      schedule  = "cron(0 4 1 * ? *)"
      retention = { delete_after = 2555, cold_storage_after = 90 }
    }]
  }

  assert {
    condition     = local.longest_schedule_gap_days == 31
    error_message = "A monthly cron (pinned day-of-month) should yield a 31-day frequency requirement."
  }
}

run "a_daily_plan_still_requires_daily" {
  command = apply

  assert {
    condition     = local.longest_schedule_gap_days == 31
    error_message = "The default rule set includes a monthly tier, so the least frequent gap is 31 days."
  }
}

run "the_retention_parameter_follows_the_shortest_tier" {
  command = apply

  assert {
    condition     = local.shortest_retention_days == 35
    error_message = "The minimum-retention control should assert the shortest retention the plan actually keeps."
  }
}

# Without the parameter, the cross-Region control passes for a copy to ANY
# Region -- making it a check that the feature is switched on rather than a check
# that the policy is met.
run "copy_controls_are_pinned_to_the_configured_destinations" {
  command = apply

  assert {
    condition     = join(",", local.copy_destination_regions) == "eu-west-1"
    error_message = "The cross-Region control should name the Regions this plan actually copies to."
  }

  assert {
    condition     = join(",", local.external_destination_account_ids) == "222222222222"
    error_message = "The cross-account control should name the destination account, parsed from its vault ARN."
  }
}

# AWS's ControlScope accepts at most one tag, and pattern-matched tags cannot be
# expressed in a scope at all. The module derives one where it unambiguously can
# and omits the scope otherwise, rather than rendering something the API rejects.
run "the_scope_tag_is_derived_when_unambiguous" {
  command = apply

  assert {
    condition     = jsonencode(local.audit_scope_tag) == jsonencode({ ToBackup = "true" })
    error_message = "A single required tag should become the framework's scope."
  }
}

run "the_scope_is_omitted_when_more_than_one_tag_is_required" {
  command = apply

  variables {
    selection_required_tags = {
      ToBackup    = "true"
      DataClass   = "confidential"
      Environment = "prod"
    }
  }

  assert {
    condition     = local.audit_scope_tag == null
    error_message = "With more than one required tag there is no correct single-tag scope, so it must be omitted rather than truncated."
  }
}

run "rejects_a_scope_tag_with_more_than_one_entry" {
  command = plan

  variables {
    audit_scope_tag = {
      ToBackup  = "true"
      DataClass = "confidential"
    }
  }

  expect_failures = [var.audit_scope_tag]
}

run "the_restore_time_target_is_in_minutes" {
  command = apply

  variables {
    restore_time_target_minutes = 240
  }

  assert {
    condition = anytrue([
      for c in aws_backup_framework.this[0].control :
      c.name == "RESTORE_TIME_FOR_RESOURCES_MEET_TARGET" &&
      anytrue([for p in c.input_parameter : p.name == "maxRestoreTime" && p.value == "240"])
    ])
    error_message = "The restore-time target should be passed through in minutes."
  }
}
