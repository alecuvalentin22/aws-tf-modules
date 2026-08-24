###############################################################################
# The full topology from the brief, in one configuration.
#
#   Prod account / Frankfurt   plan + primary vault
#   Prod account / Ireland     cross-REGION copy target
#   Backup account / Frankfurt cross-ACCOUNT copy target, isolated blast radius
#
# Note the asymmetry, and that it is deliberate:
#
#   The two prod-account vaults are created by ONE module call with no provider
#   alias, because the AWS provider places each resource in its own Region.
#
#   The backup-account vault is a SEPARATE module call through an aliased
#   provider. That boundary is the point of the design -- an isolated account
#   exists to survive a compromise of this one, so it gets its own credentials
#   and, in any real deployment, its own state file and its own pipeline.
#   Wiring both into a single apply here is a convenience for demonstrating the
#   whole picture; see the note at the bottom.
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

###############################################################################
# 1. The isolated destination, in the backup account.
#
# Created first: the policy below needs its ARN, and its vault policy and KMS
# key policy both have to name the prod account before any copy can land.
###############################################################################

module "backup_account_vault" {
  source = "../../modules/backup-vault"

  providers = {
    aws = aws.backup_account
  }

  name   = "${var.name}-isolated"
  region = var.primary_region

  # Both the vault policy and the key policy grant this account. Granting only
  # one of them is the usual reason a cross-account copy silently never arrives.
  source_account_ids = [data.aws_caller_identity.prod.account_id]

  lock = {
    enabled            = true
    mode               = var.vault_lock_mode
    min_retention_days = 7
    max_retention_days = 3650
  }

  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  # The break-glass role is exempt from the deny-delete policy. It is NOT exempt
  # from Vault Lock -- nothing is, which is the point.
  deny_delete_principals_except = var.break_glass_role_arns

  tags = var.tags
}

###############################################################################
# 2. The plan, its vaults and its controls, in the prod account.
###############################################################################

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
    }
  }

  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  # ---------------------------------------------------------------------------
  # Three tiers.
  #
  # Copy targets differ per tier on purpose. Replicating every daily point into a
  # second account triples the storage bill for the tier least likely to be the
  # one restored from; the long-lived tiers are the ones worth putting behind an
  # account boundary.
  # ---------------------------------------------------------------------------
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
      # in cold storage. The cross-Region copy is the operational one and can be
      # shorter without weakening the retention guarantee.
      copy_retention = {
        secondary_region = { delete_after = 365 }
        backup_account   = { delete_after = 2555, cold_storage_after = 90 }
      }
    },
  ]

  # ---------------------------------------------------------------------------
  # Selection: ToBackup=true AND an owner. Both, not either.
  # ---------------------------------------------------------------------------
  selection_required_tags = {
    ToBackup = "true"
  }

  selection_required_tag_patterns = {
    Owner = var.owner_tag_pattern
  }

  notification_subscriptions = var.notification_subscriptions

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
