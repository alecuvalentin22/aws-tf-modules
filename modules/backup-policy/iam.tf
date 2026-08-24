###############################################################################
# Service role
#
# AWS Backup assumes this role to read the protected resources and write recovery
# points. The AWS managed policies are used deliberately: they are extended by AWS
# whenever a new resource type becomes supported, so a hand-rolled equivalent
# silently stops covering "all supported resources" the moment the estate grows.
#
# The inline policy adds what the managed policies do not: explicit permission on
# the destination vaults and their keys, which is what cross-Region and
# cross-account copy actually needs.
###############################################################################

data "aws_iam_policy_document" "backup_assume" {
  count = var.backup_role_arn == null ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    # Confused-deputy guard: only AWS Backup acting on behalf of this account.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:backup:*:${local.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "backup" {
  count = var.backup_role_arn == null ? 1 : 0

  name                 = "${var.name}-service-role"
  description          = "Assumed by AWS Backup for the ${var.name} plan"
  assume_role_policy   = data.aws_iam_policy_document.backup_assume[0].json
  max_session_duration = 3600
  tags                 = local.tags
}

locals {
  backup_managed_policies = var.backup_role_arn == null ? {
    backup     = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    restores   = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
    s3_backup  = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForS3Backup"
    s3_restore = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForS3Restore"
  } : {}

  # Keys the role must be able to use: the primary vault's, plus every managed
  # destination's. External destinations' keys are granted from the other side.
  vault_key_arns = concat(
    [module.primary_vault.kms_key_arn],
    [for k, m in module.copy_vault : m.kms_key_arn],
  )

  all_destination_vault_arns = values(local.destination_vault_arns)
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = local.backup_managed_policies

  role       = aws_iam_role.backup[0].name
  policy_arn = each.value
}

data "aws_iam_policy_document" "backup_copy" {
  count = var.backup_role_arn == null ? 1 : 0

  dynamic "statement" {
    for_each = length(local.all_destination_vault_arns) > 0 ? [1] : []

    content {
      sid       = "CopyIntoDestinationVaults"
      effect    = "Allow"
      actions   = ["backup:CopyIntoBackupVault"]
      resources = local.all_destination_vault_arns
    }
  }

  statement {
    sid    = "UseVaultKeys"
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
    resources = local.vault_key_arns
  }

  statement {
    sid       = "GrantOnVaultKeysForAWSResources"
    effect    = "Allow"
    actions   = ["kms:CreateGrant"]
    resources = local.vault_key_arns

    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "backup_copy" {
  count = var.backup_role_arn == null ? 1 : 0

  name   = "${var.name}-copy-and-encrypt"
  role   = aws_iam_role.backup[0].id
  policy = data.aws_iam_policy_document.backup_copy[0].json
}
