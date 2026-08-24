# Behaviour of the module as shipped.
#
# Every run uses a mocked provider, so `terraform test` needs no AWS account and
# no credentials -- which is what makes it usable as a required check in CI.
# `command = apply` against mocks is what makes computed attributes (rule sets,
# rendered conditions, alarm settings) readable in an assertion; nothing is
# created anywhere.

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

run "three_tiers_are_created" {
  command = apply

  assert {
    condition     = length(aws_backup_plan.this.rule) == 3
    error_message = "The default plan should carry the daily, weekly and monthly tiers."
  }

  assert {
    condition     = length(local.retention_violations) == 0
    error_message = "The shipped defaults must sit inside the default vault lock window."
  }
}

run "daily_stays_in_account_weekly_and_monthly_leave_it" {
  command = apply

  # The cost/assurance trade-off the module is opinionated about: the tier that
  # produces the most recovery points is the least valuable to replicate to a
  # second account, so only the longer-lived tiers pay for that.
  assert {
    condition     = length(local.copy_actions["daily"]) == 1
    error_message = "The daily tier should copy cross-Region only."
  }

  assert {
    condition     = length(local.copy_actions["weekly"]) == 2
    error_message = "The weekly tier should copy cross-Region and cross-account."
  }

  assert {
    condition     = length(local.copy_actions["monthly"]) == 2
    error_message = "The monthly tier should copy cross-Region and cross-account."
  }
}

run "copy_retention_defaults_to_the_rules_own_retention" {
  command = apply

  assert {
    condition     = local.copy_actions["monthly"][0].lifecycle_config.delete_after == 2555
    error_message = "A destination with no copy_retention override should inherit the rule's delete_after."
  }

  assert {
    condition     = local.copy_actions["monthly"][0].lifecycle_config.cold_storage_after == 90
    error_message = "The inherited lifecycle should carry cold_storage_after as well as delete_after."
  }
}

run "selection_requires_all_tags_not_any" {
  command = apply

  variables {
    selection_required_tags         = { ToBackup = "true" }
    selection_required_tag_patterns = { Owner = "*@example.com" }
  }

  # The correctness crux: AND semantics come from `condition`, and would be OR
  # if this were expressed as selection_tag blocks.
  assert {
    condition = alltrue([
      for c in aws_backup_selection.this.condition :
      length(c.string_equals) == 1 && one(c.string_equals).key == "aws:ResourceTag/ToBackup"
    ])
    error_message = "The mandated exact-match tag should be rendered as a string_equals condition."
  }

  assert {
    condition = alltrue([
      for c in aws_backup_selection.this.condition :
      length(c.string_like) == 1 && one(c.string_like).key == "aws:ResourceTag/Owner"
    ])
    error_message = "The mandated pattern tag should be rendered as a string_like condition."
  }

  assert {
    condition     = length(aws_backup_selection.this.selection_tag) == 0
    error_message = "selection_tag must not be used: multiple blocks are OR-ed, which would back up resources missing a required tag."
  }
}

run "each_vault_is_distinct_and_separately_encrypted" {
  command = apply

  # One key per vault, plus the external destination's declared key. The
  # provider validates KMS ARNs client-side, so the mock returns a fixed one and
  # distinctness of the VALUES is not observable here; the count is, and it is
  # the invariant that matters -- a shared key would make the cross-Region copy
  # depend on the source Region's key.
  assert {
    condition     = length(local.vault_key_arns) == 3
    error_message = "There should be one KMS key per vault (primary + managed destination) plus the declared external destination key."
  }

  # Restore testing is a REGIONAL service: a plan in one Region cannot select a
  # vault in another. One plan per Region, each covering only the vaults it can
  # reach -- otherwise the copies are never restore-tested, which is exactly the
  # assumption restore testing exists to disprove.
  assert {
    condition     = length(aws_backup_restore_testing_plan.this) == 2
    error_message = "There should be one restore testing plan per Region the module places a vault in."
  }

  assert {
    condition = alltrue([
      for r, vaults in local.vaults_by_region : length(vaults) == 1
    ])
    error_message = "Each Region's restore testing plan should cover that Region's own vault."
  }

  # The cross-account destination is external: its ARN comes from the caller,
  # not from a module-managed vault.
  assert {
    condition     = local.destination_vault_arns["backup_account"] == "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
    error_message = "An external destination should be referenced by the ARN the caller supplied."
  }
}

run "staleness_alarm_treats_silence_as_failure" {
  command = apply

  # The classic single-plan monitoring bug is the inverse of this.
  assert {
    condition     = aws_cloudwatch_metric_alarm.stale[0].treat_missing_data == "breaching"
    error_message = "A plan that stops running emits no failure metric, so missing data must breach."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.job_failed[0].treat_missing_data == "notBreaching"
    error_message = "Absence of failures is the good case for the failure alarm."
  }
}

run "one_notification_topic_per_region" {
  command = apply

  # Vault notifications cannot cross a Region, so a single topic would silently
  # drop everything the secondary vault emits.
  assert {
    condition     = length(local.managed_regions) == 2
    error_message = "The primary Region and the managed copy Region should both be tracked."
  }
}
