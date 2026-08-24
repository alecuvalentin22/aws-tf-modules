###############################################################################
# One backup vault: the KMS key that encrypts it, the WORM lock that protects
# its recovery points, the access policy that says who may write into it, and
# the notification wiring.
#
# Kept as a leaf module because Terraform cannot iterate over provider
# configurations. Composing this module N times is the only way to express
# "the same vault, in a different place" without copy-pasting a KMS key, a
# lock and a policy per location -- which is what the naive shape of this
# module ends up doing.
###############################################################################

locals {
  # `region = null` inherits the provider's Region, which is what the AWS
  # provider does with an unset region argument anyway.
  region = var.region

  is_compliance_lock = var.lock.enabled && var.lock.mode == "compliance"

  # A non-null changeable_for_days is what selects COMPLIANCE mode in the API.
  # Governance locks must omit it entirely.
  changeable_for_days = local.is_compliance_lock ? var.lock.changeable_for_days : null

  kms_key_arn = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  tags = merge(var.tags, { BackupVault = var.name })
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

###############################################################################
# Encryption
#
# A cross-Region or cross-account copy is re-encrypted with a key that lives in
# the destination, so each vault owns its key rather than sharing one.
###############################################################################

data "aws_iam_policy_document" "kms" {
  count = var.create_kms_key ? 1 : 0

  # Without this the key is unmanageable: KMS refuses a policy that locks out
  # every principal, and IAM policies in the account cannot grant access to a
  # key whose own policy does not delegate to the account.
  statement {
    sid       = "EnableAccountIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowAWSBackupService"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:ReEncryptFrom",
      "kms:ReEncryptTo",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    # Confused-deputy guard: AWS Backup may use this key only when acting for an
    # account we expect, not for an arbitrary third party that names our key ARN.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = concat([data.aws_caller_identity.current.account_id], var.source_account_ids)
    }
  }

  statement {
    sid       = "AllowAWSBackupGrants"
    effect    = "Allow"
    actions   = ["kms:CreateGrant"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  # Cross-account copy: the SOURCE account's backup role calls KMS in this
  # account to write the copy. Without this the copy job fails with AccessDenied
  # on the destination key, which is the single most common cause of a
  # cross-account copy that silently never lands.
  dynamic "statement" {
    for_each = length(var.source_account_ids) > 0 ? [1] : []

    content {
      sid    = "AllowSourceAccountsToCopyIn"
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
        "kms:CreateGrant",
      ]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [for a in var.source_account_ids : "arn:${data.aws_partition.current.partition}:iam::${a}:root"]
      }

    }
  }
}

resource "aws_kms_key" "this" {
  count  = var.create_kms_key ? 1 : 0
  region = local.region

  description             = "Encrypts AWS Backup vault ${var.name}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = var.kms_enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms[0].json
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  count  = var.create_kms_key ? 1 : 0
  region = local.region

  name          = "alias/backup/${var.name}"
  target_key_id = aws_kms_key.this[0].key_id
}

###############################################################################
# The vault
###############################################################################

resource "aws_backup_vault" "this" {
  region = local.region

  name          = var.name
  kms_key_arn   = local.kms_key_arn
  force_destroy = false
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = var.create_kms_key || var.kms_key_arn != null
      error_message = "A vault must be encrypted: set create_kms_key = true or supply kms_key_arn."
    }
  }
}

###############################################################################
# WORM protection
#
# Two independent controls, because they fail differently:
#
#   Vault Lock       enforced by the service. In compliance mode it cannot be
#                    removed, so it holds against a compromised administrator.
#                    It cannot be applied retroactively to tighten a mistake.
#   Access policy    an ordinary resource policy. Removable by an administrator,
#                    so it is not a ransomware control -- but it is editable,
#                    takes effect immediately, and covers the governance-mode
#                    window before the lock is committed.
###############################################################################

resource "aws_backup_vault_lock_configuration" "this" {
  count  = var.lock.enabled ? 1 : 0
  region = local.region

  backup_vault_name   = aws_backup_vault.this.name
  changeable_for_days = local.changeable_for_days
  min_retention_days  = var.lock.min_retention_days
  max_retention_days  = var.lock.max_retention_days

  lifecycle {
    precondition {
      condition     = !local.is_compliance_lock || var.confirm_irreversible_compliance_lock
      error_message = <<-EOT
        Refusing to create a COMPLIANCE-mode Vault Lock on "${var.name}" without acknowledgement.

        A compliance lock is permanent once its ${var.lock.changeable_for_days}-day grace period elapses:
        retention cannot be shortened, recovery points cannot be deleted early, the vault cannot
        be destroyed while it holds them, and no principal -- including the account root -- can
        undo it.

        Validate in governance mode first (lock.mode = "governance"), prove a backup, a copy and a
        restore, then set confirm_irreversible_compliance_lock = true and switch the mode.
      EOT
    }
  }
}

data "aws_iam_policy_document" "vault" {
  count = var.enable_deny_delete_policy || length(var.source_account_ids) > 0 ? 1 : 0

  # Cross-account copy destinations must name the source accounts explicitly.
  dynamic "statement" {
    for_each = length(var.source_account_ids) > 0 ? [1] : []

    content {
      sid       = "AllowSourceAccountsToCopyIn"
      effect    = "Allow"
      actions   = ["backup:CopyIntoBackupVault"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = [for a in var.source_account_ids : "arn:${data.aws_partition.current.partition}:iam::${a}:root"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_deny_delete_policy ? [1] : []

    content {
      sid    = "DenyDeletion"
      effect = "Deny"
      actions = [
        "backup:DeleteRecoveryPoint",
        "backup:UpdateRecoveryPointLifecycle",
        "backup:DeleteBackupVault",
        "backup:DeleteBackupVaultLockConfiguration",
        "backup:DeleteBackupVaultAccessPolicy",
        "backup:PutBackupVaultAccessPolicy",
      ]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      dynamic "condition" {
        for_each = length(var.deny_delete_principals_except) > 0 ? [1] : []

        content {
          test     = "ArnNotLike"
          variable = "aws:PrincipalArn"
          values   = var.deny_delete_principals_except
        }
      }
    }
  }
}

resource "aws_backup_vault_policy" "this" {
  count  = var.enable_deny_delete_policy || length(var.source_account_ids) > 0 ? 1 : 0
  region = local.region

  backup_vault_name = aws_backup_vault.this.name
  policy            = data.aws_iam_policy_document.vault[0].json
}

###############################################################################
# Notifications
#
# Vault notifications are Region- and account-local: the topic must live beside
# the vault. The parent module therefore creates one topic per location rather
# than fanning every vault into a single topic.
###############################################################################

resource "aws_backup_vault_notifications" "this" {
  count  = var.enable_notifications ? 1 : 0
  region = local.region

  lifecycle {
    precondition {
      condition     = var.notification_sns_topic_arn != null
      error_message = "notification_sns_topic_arn is required when enable_notifications is true."
    }
  }

  backup_vault_name   = aws_backup_vault.this.name
  sns_topic_arn       = var.notification_sns_topic_arn
  backup_vault_events = var.notification_events
}
