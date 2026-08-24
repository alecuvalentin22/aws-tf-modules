# Scaling the copy topology.
#
# The reason this module composes a child module over a map instead of writing
# one vault, one key and one lock per location: adding a Region is a map entry,
# not a new provider alias plus a copy of every resource in the module.
#
# This is what the AWS provider's per-resource `region` argument buys. Terraform
# cannot iterate over provider configurations, so the conventional shape of this
# module is hard-wired to a fixed set of locations.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name = "platform-backup"

  copy_destinations = {
    ireland   = { region = "eu-west-1" }
    london    = { region = "eu-west-2" }
    stockholm = { region = "eu-north-1" }
    milan     = { region = "eu-south-1" }

    backup_account = {
      vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
      lock_min_retention_days = 7
      lock_max_retention_days = 3650
      kms_key_arn_external    = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
    }
  }

  rules = [{
    name      = "daily"
    schedule  = "cron(0 2 * * ? *)"
    retention = { delete_after = 35 }
    copy_to   = ["ireland", "london", "stockholm", "milan", "backup_account"]
  }]
}

run "four_regions_plus_a_cross_account_target" {
  command = apply

  assert {
    condition     = length(module.copy_vault) == 4
    error_message = "Each managed Region should get its own vault, key and lock."
  }

  assert {
    condition     = length(local.external_destinations) == 1
    error_message = "The cross-account destination is external: a different account needs different credentials, so it is deployed separately and referenced by ARN."
  }

  assert {
    condition     = length(local.copy_actions["daily"]) == 5
    error_message = "One copy action per destination."
  }
}

run "one_sns_topic_per_region_not_one_per_plan" {
  command = apply

  # Vault notifications cannot cross a Region. A single topic in the primary
  # Region would drop everything the other four vaults emit.
  assert {
    condition     = length(local.managed_regions) == 5
    error_message = "The primary Region plus four copy Regions should each get a topic."
  }

  assert {
    condition     = length(aws_sns_topic.backup) == 5
    error_message = "One SNS topic per Region the module places a vault in."
  }
}

run "the_backup_role_can_reach_every_destination" {
  command = apply

  # A copy action fails with AccessDenied if the role cannot write to the
  # destination vault or use its key, and the failure surfaces as a copy job
  # error at 02:00, not at apply time.
  assert {
    condition     = length(local.all_destination_vault_arns) == 5
    error_message = "The role's copy permissions should cover every destination, managed and external."
  }

  # Primary + four managed destinations + the external destination's key.
  #
  # The external one is the easy one to miss: a destination key policy granting
  # arn:aws:iam::<source>:root DELEGATES to the source account's IAM, it does not
  # authorise anything by itself. Without a matching IAM allow here, every
  # encrypted cross-account copy fails with AccessDenied on the destination key.
  assert {
    condition     = length(local.vault_key_arns) == 6
    error_message = "The role should be granted the primary key, each managed destination key, and each declared external destination key."
  }

  assert {
    condition = contains(
      local.vault_key_arns,
      "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333",
    )
    error_message = "The external (cross-account) destination's KMS key must be named in the backup role's policy."
  }
}
