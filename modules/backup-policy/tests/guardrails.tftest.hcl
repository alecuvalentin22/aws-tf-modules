# The failure modes this module exists to prevent.
#
# Each run supplies a configuration that AWS would accept at apply time and then
# fail on, silently, in production. The assertion is that Terraform refuses it
# first. A guardrail with no test proving it fires is decoration.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name = "platform-backup"

  copy_destinations = {
    secondary_region = {
      region = "eu-west-1"
    }
  }

  # A deliberately minimal baseline. The shipped default rules copy to
  # `backup_account`, which most runs below do not define; without this, the
  # unknown-destination precondition would fire first and mask the guardrail
  # each run is actually trying to prove.
  rules = [{
    name      = "daily"
    schedule  = "cron(0 2 * * ? *)"
    retention = { delete_after = 35 }
  }]
}

# --------------------------------------------------------------------------
# Vault Lock retention window
#
# The nastiest trap in AWS Backup. A vault lock rejects jobs whose delete_after
# falls outside its window -- at RUN time, every night, long after the apply that
# introduced the mismatch reported success. Nothing in the apply output hints at
# it, and on a compliance lock the window cannot be widened to fix it.
# --------------------------------------------------------------------------

run "rejects_retention_below_the_vault_lock_minimum" {
  command = plan

  variables {
    rules = [{
      name      = "too-short"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 3 } # lock minimum defaults to 7
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

run "rejects_retention_above_the_vault_lock_maximum" {
  command = plan

  variables {
    primary_vault = {
      lock = {
        enabled            = true
        min_retention_days = 7
        max_retention_days = 365
      }
    }

    rules = [{
      name      = "too-long"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 2555 }
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

# A copy is checked against the DESTINATION's window, not the source's. Checking
# only one global window is the mistake that lets a cross-account copy fail every
# night while the local backup succeeds.
run "rejects_a_copy_retention_outside_the_destinations_window" {
  command = plan

  variables {
    copy_destinations = {
      secondary_region = {
        region = "eu-west-1"
        lock = {
          enabled            = true
          min_retention_days = 30
          max_retention_days = 365
        }
      }
    }

    rules = [{
      name           = "daily"
      schedule       = "cron(0 2 * * ? *)"
      retention      = { delete_after = 35 } # fine locally
      copy_to        = ["secondary_region"]
      copy_retention = { secondary_region = { delete_after = 7 } } # below the destination minimum
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

# An external (cross-account) destination can be checked too, as long as the
# caller declares the window its Vault Lock enforces.
run "rejects_a_cross_account_copy_outside_the_declared_external_window" {
  command = plan

  variables {
    copy_destinations = {
      backup_account = {
        vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
        lock_min_retention_days = 90
        lock_max_retention_days = 3650
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["backup_account"]
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

run "accepts_retention_that_sits_inside_every_window" {
  command = plan

  variables {
    copy_destinations = {
      secondary_region = {
        region = "eu-west-1"
        lock = {
          enabled            = true
          min_retention_days = 30
          max_retention_days = 400
        }
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["secondary_region"]
    }]
  }

  assert {
    condition     = length(local.retention_violations) == 0
    error_message = "A retention inside every destination's window must be accepted."
  }
}

# --------------------------------------------------------------------------
# Typos that would otherwise fail silently
# --------------------------------------------------------------------------

run "rejects_a_copy_to_a_destination_that_does_not_exist" {
  command = plan

  variables {
    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["typo_region"]
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

run "rejects_a_copy_retention_override_for_a_destination_not_copied_to" {
  command = plan

  variables {
    rules = [{
      name           = "daily"
      schedule       = "cron(0 2 * * ? *)"
      retention      = { delete_after = 35 }
      copy_to        = []
      copy_retention = { secondary_region = { delete_after = 35 } }
    }]
  }

  expect_failures = [var.rules]
}

# --------------------------------------------------------------------------
# AWS lifecycle rules, enforced at plan time instead of at job time
# --------------------------------------------------------------------------

run "rejects_a_cold_storage_transition_less_than_90_days_before_expiry" {
  command = plan

  variables {
    rules = [{
      name      = "monthly"
      schedule  = "cron(0 4 1 * ? *)"
      retention = { delete_after = 120, cold_storage_after = 90 }
    }]
  }

  expect_failures = [var.rules]
}

run "rejects_continuous_backup_with_retention_beyond_35_days" {
  command = plan

  variables {
    rules = [{
      name                     = "pitr"
      schedule                 = "cron(0 2 * * ? *)"
      enable_continuous_backup = true
      retention                = { delete_after = 90 }
    }]
  }

  expect_failures = [var.rules]
}

run "rejects_archive_opt_in_without_a_cold_storage_transition" {
  command = plan

  variables {
    rules = [{
      name      = "monthly"
      schedule  = "cron(0 4 1 * ? *)"
      retention = { delete_after = 2555, opt_in_to_archive_for_supported_resources = true }
    }]
  }

  expect_failures = [var.rules]
}

run "rejects_a_schedule_that_is_not_a_cron_or_rate_expression" {
  command = plan

  variables {
    rules = [{
      name      = "daily"
      schedule  = "every day at 2am"
      retention = { delete_after = 35 }
    }]
  }

  expect_failures = [var.rules]
}

run "rejects_duplicate_rule_names" {
  command = plan

  variables {
    rules = [
      { name = "daily", schedule = "cron(0 2 * * ? *)", retention = { delete_after = 35 } },
      { name = "daily", schedule = "cron(0 3 * * ? *)", retention = { delete_after = 90 } },
    ]
  }

  expect_failures = [var.rules]
}

# --------------------------------------------------------------------------
# Selection safety
# --------------------------------------------------------------------------

run "rejects_an_unconditional_selection" {
  command = plan

  # resources = ["*"] with no tag condition backs up every resource in the
  # account, which is a budget incident rather than a backup policy.
  variables {
    selection_required_tags = {}
  }

  expect_failures = [var.selection_required_tags]
}

# --------------------------------------------------------------------------
# Copy destination shape
# --------------------------------------------------------------------------

run "rejects_a_destination_that_is_both_managed_and_external" {
  command = plan

  variables {
    copy_destinations = {
      confused = {
        region    = "eu-west-1"
        vault_arn = "arn:aws:backup:eu-west-1:222222222222:backup-vault:other"
      }
    }
  }

  expect_failures = [var.copy_destinations]
}

run "rejects_a_destination_that_is_neither_managed_nor_external" {
  command = plan

  variables {
    copy_destinations = {
      empty = {}
    }
  }

  expect_failures = [var.copy_destinations]
}

run "rejects_a_malformed_external_vault_arn" {
  command = plan

  variables {
    copy_destinations = {
      backup_account = {
        vault_arn = "platform-iso"
      }
    }
  }

  expect_failures = [var.copy_destinations]
}

# --------------------------------------------------------------------------
# Regression tests for defects found in review.
#
# Each of these was a way for the module's headline guarantee -- "retention is
# validated against the destination's Vault Lock window at plan time" -- to
# pass while doing nothing. A guardrail that fails open is worse than no
# guardrail, because it is trusted.
# --------------------------------------------------------------------------

# The primary vault's lock window used to be merged into the same map as the
# copy destinations under a "__primary__" sentinel key, and the destination-key
# regex permitted that exact string. A destination so named overwrote the
# primary vault's window, and its retention check then passed for any value.
#
# The primary window now lives in its own local, so the collision is structurally
# impossible rather than merely discouraged. This asserts the check fires: the
# rule below keeps 5 days against a primary minimum of 30.
run "a_destination_cannot_impersonate_the_primary_vault" {
  command = plan

  variables {
    primary_vault = {
      lock = {
        enabled            = true
        min_retention_days = 30
        max_retention_days = 60
      }
    }

    copy_destinations = {
      __primary__ = {
        region = "eu-west-1"
        lock = {
          enabled            = true
          min_retention_days = 1
          max_retention_days = 3650
        }
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 5 } # below the PRIMARY vault's minimum of 30
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

# An external destination whose lock window is not declared cannot be checked.
# That used to be a silent skip, on the one hop with the least visibility and
# the strictest lock. It is now an error unless explicitly acknowledged.
run "rejects_an_external_destination_with_no_declared_lock_window" {
  command = plan

  variables {
    copy_destinations = {
      backup_account = {
        vault_arn            = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
        kms_key_arn_external = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["backup_account"]
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

run "an_unchecked_destination_can_be_accepted_knowingly_and_is_still_named" {
  command = apply

  variables {
    acknowledge_unchecked_copy_destinations = true

    copy_destinations = {
      backup_account = {
        vault_arn            = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
        kms_key_arn_external = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["backup_account"]
    }]
  }

  assert {
    condition     = join(",", local.unchecked_destinations) == "backup_account"
    error_message = "A destination whose window could not be checked must still be named, so the gap is visible rather than silent."
  }
}

# An encrypted cross-account copy needs the source role allowed on the
# DESTINATION key. The destination key policy granting <source>:root only
# delegates to that account's IAM; it authorises nothing by itself.
run "rejects_an_external_destination_with_no_kms_key_arn" {
  command = plan

  variables {
    copy_destinations = {
      backup_account = {
        vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
        lock_min_retention_days = 7
        lock_max_retention_days = 3650
      }
    }

    rules = [{
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["backup_account"]
    }]
  }

  expect_failures = [aws_backup_plan.this]
}

# A partial copy_retention override used to REPLACE the rule's lifecycle
# wholesale, so `{ delete_after = 2555 }` on a rule with cold_storage_after = 90
# produced a seven-year copy kept entirely in warm storage -- roughly an order
# of magnitude more expensive, with nothing in the plan to show it.
run "a_partial_copy_retention_override_inherits_the_rest_of_the_lifecycle" {
  command = apply

  variables {
    copy_destinations = {
      secondary_region = { region = "eu-west-1" }
    }

    rules = [{
      name      = "monthly"
      schedule  = "cron(0 4 1 * ? *)"
      retention = { delete_after = 2555, cold_storage_after = 90 }
      copy_to   = ["secondary_region"]

      copy_retention = {
        secondary_region = { delete_after = 2555 }
      }
    }]
  }

  assert {
    condition     = local.copy_actions["monthly"][0].lifecycle_config.cold_storage_after == 90
    error_message = "An override that does not mention cold_storage_after must inherit it, not drop it."
  }

  assert {
    condition     = local.copy_actions["monthly"][0].lifecycle_config.delete_after == 2555
    error_message = "The overridden field should still take effect."
  }
}

run "an_explicit_copy_retention_override_wins_over_the_rules_lifecycle" {
  command = apply

  variables {
    copy_destinations = {
      secondary_region = { region = "eu-west-1" }
    }

    rules = [{
      name      = "monthly"
      schedule  = "cron(0 4 1 * ? *)"
      retention = { delete_after = 2555, cold_storage_after = 90 }
      copy_to   = ["secondary_region"]

      copy_retention = {
        secondary_region = { delete_after = 400, cold_storage_after = 180 }
      }
    }]
  }

  assert {
    condition     = local.copy_actions["monthly"][0].lifecycle_config.cold_storage_after == 180
    error_message = "An explicitly overridden field must win."
  }
}

# AWS rejects a completion window equal to the start window.
run "rejects_a_completion_window_equal_to_the_start_window" {
  command = plan

  variables {
    rules = [{
      name                      = "daily"
      schedule                  = "cron(0 2 * * ? *)"
      start_window_minutes      = 60
      completion_window_minutes = 60
      retention                 = { delete_after = 35 }
    }]
  }

  expect_failures = [var.rules]
}

# Copying CONTINUOUS recovery points is only supported for some resource types.
run "rejects_continuous_backup_with_copies_unless_acknowledged" {
  command = plan

  variables {
    rules = [{
      name                     = "pitr"
      schedule                 = "cron(0 2 * * ? *)"
      enable_continuous_backup = true
      retention                = { delete_after = 35 }
      copy_to                  = ["secondary_region"]
    }]
  }

  expect_failures = [var.rules]
}
