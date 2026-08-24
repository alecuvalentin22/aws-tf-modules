###############################################################################
# One backup vault: the KMS key that encrypts it, the WORM lock that protects
# its recovery points, and the access policy that says who may write into it.
#
# Kept as a leaf module because Terraform cannot iterate over provider
# configurations. Composing this module N times is the only way to express
# "the same vault, in a different place" without copy-pasting a KMS key, a
# lock and a policy per location, which is what the naive shape of this
# module ends up doing, and those copies then drift.
#
# Policies are built with jsonencode rather than aws_iam_policy_document on
# purpose. A `terraform test` running against a mocked provider cannot compute
# a data source, so policy documents built that way render as an empty
# placeholder and every statement in them goes untested. These are the
# security-carrying part of the module; they are worth being able to assert on.
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  # `region = null` inherits the provider's Region, which is what the AWS
  # provider does with an unset region argument anyway.
  region        = var.region
  actual_region = coalesce(var.region, data.aws_region.current.region)

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  is_compliance_lock = var.lock.enabled && var.lock.mode == "compliance"

  # A non-null changeable_for_days is what selects COMPLIANCE mode in the API.
  # Governance locks must omit it entirely.
  changeable_for_days = local.is_compliance_lock ? var.lock.changeable_for_days : null

  kms_key_arn = var.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  tags = merge(var.tags, { BackupVault = var.name })

  source_account_arns = [
    for a in var.source_account_ids : "arn:${local.partition}:iam::${a}:root"
  ]

  # Guard list for the cross-account statements. A `cond ? [] : [a, b]` ternary
  # cannot be used here: HCL requires both branches of a conditional to have the
  # same type, and an empty tuple never matches a two-element one.
  cross_account = length(var.source_account_ids) > 0 ? [1] : []

  # Naming the source ROLE rather than the account root is the strongest available
  # narrowing, and unlike a condition key it cannot be absent from a request.
  # Defaults to the account root because that is what a caller can always supply;
  # narrow it wherever the source role ARN is known.
  cross_account_principals = length(var.source_principal_arns) > 0 ? var.source_principal_arns : local.source_account_arns

  # AWS Backup's service-principal name in kms:ViaService is Region-qualified.
  backup_via_service = "backup.${local.actual_region}.amazonaws.com"

  kms_data_plane_actions = [
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyWithoutPlaintext",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
  ]
}

###############################################################################
# Encryption
#
# A cross-Region or cross-account copy is re-encrypted with a key that lives in
# the destination, so each vault owns its key rather than sharing one.
###############################################################################

locals {
  kms_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # Without this the key is unmanageable: KMS rejects a policy that locks
        # out every principal, and IAM policies in this account cannot grant
        # access to a key whose own policy does not delegate to the account.
        {
          Sid       = "EnableAccountIAMPolicies"
          Effect    = "Allow"
          Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
          Action    = "kms:*"
          Resource  = "*"
        },
        {
          Sid       = "AllowAWSBackupService"
          Effect    = "Allow"
          Principal = { Service = "backup.amazonaws.com" }
          Action    = local.kms_data_plane_actions
          Resource  = "*"
          # Confused-deputy guard: AWS Backup may use this key only when acting
          # for an account we expect. IfExists, because a plain StringEquals on
          # an absent context key evaluates false and would break the copy.
          Condition = {
            StringEqualsIfExists = {
              "aws:SourceAccount" = distinct(concat([local.account_id], var.source_account_ids))
            }
            ArnLikeIfExists = {
              "aws:SourceArn" = "arn:${local.partition}:backup:*:*:*"
            }
          }
        },
        {
          Sid       = "AllowAWSBackupGrants"
          Effect    = "Allow"
          Principal = { Service = "backup.amazonaws.com" }
          Action    = "kms:CreateGrant"
          Resource  = "*"
          Condition = {
            Bool = { "kms:GrantIsForAWSResource" = "true" }
          }
        },
      ],

      # Cross-account copy: the SOURCE account's backup role calls KMS in THIS
      # account to write the copy. Without this the copy job fails with
      # AccessDenied on the destination key, the single most common reason a
      # cross-account copy silently never lands.
      #
      # Scoped hard. Granting an external account unconditional data-plane
      # access to this key would hand an attacker holding admin in the source
      # account the ability to read everything in the isolated vault, which is
      # the exact failure this account boundary exists to prevent.
      [
        for _ in local.cross_account : {
          Sid       = "AllowSourceAccountsToCopyIn"
          Effect    = "Allow"
          Principal = { AWS = local.cross_account_principals }
          Action    = local.kms_data_plane_actions
          Resource  = "*"
          Condition = {
            # Two deliberate choices here, both about not breaking the copy.
            #
            # IfExists, because a plain StringEquals on a context key the caller
            # does not populate evaluates to FALSE and denies the request. AWS
            # Backup may authorise its copy-time KMS calls through a grant rather
            # than through this statement, in which case kms:ViaService is absent
            #, and a fail-closed condition would deny the very operation this
            # statement exists to permit, nightly, after a clean apply.
            #
            # A wildcard Region, because a cross-account destination may also be
            # cross-Region. Pinning the destination Region would not match a call
            # made from the source Region's endpoint.
            #
            # The real narrowing should come from source_principal_arns, which
            # names the source ROLE and does not depend on any context key being
            # present. kms:CallerAccount is omitted as redundant: Principal
            # already restricts this to the declared source accounts.
            StringLikeIfExists = {
              "kms:ViaService" = "backup.*.amazonaws.com"
            }
          }
        }
      ],
      [
        for _ in local.cross_account : {
          Sid       = "AllowSourceAccountsToGrantForAWSResources"
          Effect    = "Allow"
          Principal = { AWS = local.cross_account_principals }
          Action    = "kms:CreateGrant"
          Resource  = "*"
          Condition = {
            Bool = { "kms:GrantIsForAWSResource" = "true" }
          }
        }
      ],
    )
  })
}

resource "aws_kms_key" "this" {
  count  = var.create_kms_key ? 1 : 0
  region = local.region

  description             = "Encrypts AWS Backup vault ${var.name}"
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = var.kms_enable_key_rotation
  policy                  = local.kms_policy
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
  force_destroy = var.force_destroy
  tags          = local.tags

  lifecycle {
    precondition {
      condition     = var.create_kms_key || var.kms_key_arn != null
      error_message = "A vault must be encrypted: set create_kms_key = true or supply kms_key_arn."
    }

    # force_destroy deletes the vault's recovery points before the vault, which
    # needs backup:DeleteRecoveryPoint and backup:DeleteBackupVault, both denied
    # by the deny-delete policy to every principal not on the exemption list. The
    # two settings silently conflict, and the symptom is an AccessDenied on destroy
    # with nothing to say which of them caused it.
    precondition {
      condition = (
        !var.force_destroy ||
        !var.enable_deny_delete_policy ||
        length(var.deny_delete_principals_except) > 0
      )
      error_message = <<-EOT
        force_destroy is set on vault "${var.name}" while the deny-delete policy denies
        deletion to every principal, so `terraform destroy` would fail with AccessDenied.

        Either set enable_deny_delete_policy = false for this throwaway environment, or add
        the Terraform execution role to deny_delete_principals_except.

        Note that neither makes a committed COMPLIANCE lock destroyable. Nothing does.
      EOT
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
#                    so it is not a ransomware control, but it is editable,
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
        be destroyed while it holds them, and no principal. Including the account root, can
        undo it.

        Validate in governance mode first (lock.mode = "governance"), prove a backup, a copy and a
        restore, then set confirm_irreversible_compliance_lock = true and switch the mode.
      EOT
    }
  }
}

locals {
  create_vault_policy = var.enable_deny_delete_policy || length(var.source_account_ids) > 0

  vault_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # Cross-account copy destinations must name the source accounts explicitly.
      [
        for _ in local.cross_account : {
          Sid       = "AllowSourceAccountsToCopyIn"
          Effect    = "Allow"
          Principal = { AWS = local.source_account_arns }
          Action    = "backup:CopyIntoBackupVault"
          Resource  = "*"
        }
      ],

      # Defence in depth behind Vault Lock.
      #
      # Note what is NOT denied here: backup:PutBackupVaultAccessPolicy and
      # backup:DeleteBackupVaultAccessPolicy. Denying those with Principal "*"
      # makes the policy unmodifiable and unremovable by the very role that
      # created it, so the vault can never be updated to add a source account
      # or a break-glass exemption, and `terraform destroy` can never succeed.
      # A policy that cannot be corrected is a lockout, not a control; Vault
      # Lock is what provides the tamper-proof guarantee.
      [
        for _ in(var.enable_deny_delete_policy ? [1] : []) : merge(
          {
            Sid    = "DenyRecoveryPointDeletion"
            Effect = "Deny"
            Principal = {
              AWS = "*"
            }
            Action = [
              "backup:DeleteRecoveryPoint",
              "backup:UpdateRecoveryPointLifecycle",
              "backup:DeleteBackupVault",
              "backup:DeleteBackupVaultLockConfiguration",
            ]
            Resource = "*"
          },
          length(var.deny_delete_principals_except) == 0 ? {} : {
            Condition = {
              ArnNotLike = { "aws:PrincipalArn" = var.deny_delete_principals_except }
            }
          },
        )
      ],
    )
  })
}

resource "aws_backup_vault_policy" "this" {
  count  = local.create_vault_policy ? 1 : 0
  region = local.region

  backup_vault_name = aws_backup_vault.this.name
  policy            = local.vault_policy

  # Destroy ordering. The policy denies DeleteBackupVaultLockConfiguration, so
  # if Terraform removed the lock before the policy the call would be denied.
  # This edge makes the policy tear down first.
  depends_on = [aws_backup_vault_lock_configuration.this]
}
