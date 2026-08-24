
locals {
  backup_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "backup.amazonaws.com" }
        # Confused-deputy guard: only AWS Backup acting on behalf of this account.
        #
        # IfExists, not the plain operators. A StringEquals on a context key that
        # the caller does not populate evaluates to FALSE, which would make the
        # role unassumable and stop every backup job in the account, silently,
        # since nothing fails at apply time. AWS's own generated service role
        # carries no conditions at all; IfExists keeps the protection where the
        # keys are present without betting the whole plan on them always being so.
        Condition = {
          StringEqualsIfExists = {
            "aws:SourceAccount" = local.account_id
          }
          ArnLikeIfExists = {
            "aws:SourceArn" = "arn:${local.partition}:backup:*:${local.account_id}:*"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role" "backup" {
  count = var.backup_role_arn == null ? 1 : 0

  name                 = "${var.name}-service-role"
  description          = "Assumed by AWS Backup for the ${var.name} plan"
  assume_role_policy   = local.backup_assume_role_policy
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

  # Keys the role must be able to use: the primary vault's, every managed
  # destination's, and every EXTERNAL destination's whose ARN the caller
  # supplied. The last group is easy to miss: a destination key policy that
  # grants `<source-account>:root` only delegates to that account's IAM. It does
  # not authorise anything by itself, so without a matching allow here every
  # encrypted cross-account copy fails with AccessDenied on the destination key.
  vault_key_arns = concat(
    [module.primary_vault.kms_key_arn],
    [for k, m in module.copy_vault : m.kms_key_arn],
    local.external_destination_key_arns,
  )

  all_destination_vault_arns = values(local.destination_vault_arns)
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = local.backup_managed_policies

  role       = aws_iam_role.backup[0].name
  policy_arn = each.value
}

locals {
  backup_copy_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        for _ in(length(local.all_destination_vault_arns) > 0 ? [1] : []) : {
          Sid      = "CopyIntoDestinationVaults"
          Effect   = "Allow"
          Action   = "backup:CopyIntoBackupVault"
          Resource = local.all_destination_vault_arns
        }
      ],
      [
        {
          Sid    = "UseVaultKeys"
          Effect = "Allow"
          Action = [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:GenerateDataKeyWithoutPlaintext",
            "kms:ReEncryptFrom",
            "kms:ReEncryptTo",
          ]
          Resource = local.vault_key_arns
        },
        {
          Sid      = "GrantOnVaultKeysForAWSResources"
          Effect   = "Allow"
          Action   = "kms:CreateGrant"
          Resource = local.vault_key_arns
          Condition = {
            Bool = { "kms:GrantIsForAWSResource" = "true" }
          }
        },
      ],
    )
  })
}

resource "aws_iam_role_policy" "backup_copy" {
  count = var.backup_role_arn == null ? 1 : 0

  name   = "${var.name}-copy-and-encrypt"
  role   = aws_iam_role.backup[0].id
  policy = local.backup_copy_policy
}
