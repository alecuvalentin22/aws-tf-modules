###############################################################################
# PREREQUISITES that live outside this configuration
#
# Cross-account copy does not work without all of these, and none of them fails
# at apply time, the plan applies cleanly and the copy job fails from night
# one. Check them before treating a green apply as a working backup policy.
#
#   1. Both accounts are in the same AWS Organization.
#
#   2. `isCrossAccountBackupEnabled = true` at the organisation level. The API
#      is only valid from the Organizations MANAGEMENT account, so it is not set
#      here. The module exposes it as
#      `enable_cross_account_backup_global_setting` for the management account's
#      own configuration.
#
#   3. The AWS Backup resource types are opted in per Region. `resources = ["*"]`
#      only covers opted-in types, and an un-opted type is skipped SILENTLY --
#      the plan reports success while protecting less than it appears to. This
#      belongs in the account baseline; see the module's `opt_in_resource_types`.
#
#   4. AWS Config is recording, if the Audit Manager framework is enabled below.
#      Without it the framework deploys and evaluates nothing.
#
# Verify with a full backup -> copy -> RESTORE cycle before switching any vault
# to compliance mode. After that switch, a missing grant is a locked vault full
# of unusable recovery points.
###############################################################################

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}

provider "aws" {
  region = var.primary_region
}

provider "aws" {
  alias  = "backup_account"
  region = var.primary_region

  assume_role {
    role_arn = var.backup_account_role_arn
  }
}

data "aws_caller_identity" "prod" {}

# Created first: the policy below needs its ARN, and both its vault policy and its
# key policy have to name the prod account before any copy can land.

module "backup_account_vault" {
  source = "../../modules/backup-vault"

  providers = {
    aws = aws.backup_account
  }

  name   = "${var.name}-isolated"
  region = var.primary_region

  # Both the vault policy and the key policy grant this account. Granting only
  # one of them is the usual reason a cross-account copy never arrives.
  source_account_ids = [data.aws_caller_identity.prod.account_id]

  lock = {
    enabled            = true
    mode               = var.vault_lock_mode
    min_retention_days = 7
    max_retention_days = 3650
  }

  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  # The break-glass role is exempt from the deny-delete policy. Nothing is exempt
  # from Vault Lock.
  deny_delete_principals_except = var.break_glass_role_arns

  tags = var.tags
}

module "backup_policy" {
  source = "../.."

  name = var.name

  primary_vault = {
    region = var.primary_region

    lock = {
      enabled            = true
      mode               = var.vault_lock_mode
      min_retention_days = 7
      max_retention_days = 3650
    }
  }

  copy_destinations = {
    # Managed by this module, in another Region of this account.
    secondary_region = {
      region = var.secondary_region

      lock = {
        enabled            = true
        mode               = var.vault_lock_mode
        min_retention_days = 7
        max_retention_days = 3650
      }
    }

    # External: owned by the backup account. Declaring its lock window lets the
    # policy module reject, at plan time, a retention the destination would
    # reject nightly at run time.
    backup_account = {
      vault_arn               = module.backup_account_vault.arn
      lock_min_retention_days = module.backup_account_vault.lock.min_retention_days
      lock_max_retention_days = module.backup_account_vault.lock.max_retention_days

      # Required, and the easiest thing here to get wrong. The destination key
      # policy grants arn:aws:iam::<prod>:root, which DELEGATES to the prod
      # account's IAM. It does not authorise any principal there by itself.
      # The backup role also needs an IAM allow naming this key, and the module
      # cannot construct it without the ARN.
      kms_key_arn_external = module.backup_account_vault.kms_key_arn
    }
  }

  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  rules = [
    {
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["secondary_region"]
    },
    {
      name      = "weekly"
      schedule  = "cron(0 3 ? * SUN *)"
      retention = { delete_after = 90 }
      copy_to   = ["secondary_region", "backup_account"]
    },
    {
      name                      = "monthly"
      schedule                  = "cron(0 4 1 * ? *)"
      completion_window_minutes = 1440
      retention = {
        delete_after       = 2555 # seven years
        cold_storage_after = 90
      }
      copy_to = ["secondary_region", "backup_account"]

      # The cross-account copy is the compliance copy, so it keeps the full term
      # in cold storage. The cross-Region copy is the OPERATIONAL one, shorter,
      # and deliberately kept warm so a restore from it takes minutes rather than
      # hours.
      #
      # disable_cold_storage is what makes that expressible. Without it the copy
      # inherits the rule's 90-day transition, and the "operational" copy
      # becomes one that restores in hours, which is the opposite of its purpose,
      # and invisible in the plan.
      copy_retention = {
        secondary_region = { delete_after = 365, disable_cold_storage = true }
        backup_account   = { delete_after = 2555, cold_storage_after = 90 }
      }
    },
  ]

  selection_required_tags = {
    ToBackup = "true"
  }

  selection_required_tag_patterns = {
    Owner = var.owner_tag_pattern
  }

  notification_subscriptions = var.notification_subscriptions

  # Break-glass exemption applies to the deny-delete POLICY only. Vault Lock
  # exempts nobody.
  deny_delete_principals_except = var.break_glass_role_arns

  enable_restore_testing = true
  enable_audit_framework = true

  tags = var.tags
}

###############################################################################
# In production, split this into two states.
#
# A single state that can write to both accounts is a single credential that can
# destroy both copies, which is the failure the backup account is meant to
# survive. The intended split:
#
#   state A (backup account)  modules/backup-vault, source_account_ids = [prod]
#                             outputs the vault ARN
#   state B (prod account)    this module, with
#                             copy_destinations.backup_account.vault_arn = <that ARN>
#
# Nothing in the module changes; only which pipeline holds which credentials.
###############################################################################
