###############################################################################
# The smallest configuration that is still a real backup policy.
#
# One account, two Regions, no cross-account copy. Governance-mode locks, so it
# can be destroyed again, which is what makes it a safe first apply.
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
  region = "eu-central-1"
}

module "backup_policy" {
  source = "../.."

  name = "platform-backup"

  copy_destinations = {
    secondary_region = {
      region = "eu-west-1"
    }
  }

  rules = [
    {
      name      = "daily"
      schedule  = "cron(0 2 * * ? *)"
      retention = { delete_after = 35 }
      copy_to   = ["secondary_region"]
    },
  ]

  selection_required_tags = {
    ToBackup = "true"
  }

  selection_required_tag_patterns = {
    Owner = "*@example.com"
  }

  # Audit Manager needs AWS Config recording; leave it off until that is true.
  enable_audit_framework = false
}

output "copy_matrix" {
  value = module.backup_policy.effective_copy_matrix
}
