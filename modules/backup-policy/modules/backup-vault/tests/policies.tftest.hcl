# The policies, asserted on their rendered content.
#
# These are built with jsonencode rather than aws_iam_policy_document precisely
# so that this file can exist: a mocked provider cannot compute a data source,
# so a policy built that way renders as an empty placeholder and every statement
# in it goes untested. These policies are what actually permit, or silently
# block, a cross-account copy, and none of it is legible in a plan diff.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name               = "platform-backup-isolated"
  source_account_ids = ["111111111111"]
}

# --------------------------------------------------------------------------
# Vault access policy
# --------------------------------------------------------------------------

run "vault_policy_lets_the_source_account_copy_in" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.vault_policy).Statement :
      s.Effect == "Allow" &&
      s.Action == "backup:CopyIntoBackupVault" &&
      contains(tolist(s.Principal.AWS), "arn:aws:iam::111111111111:root")
    ])
    error_message = "The destination vault policy must name the source account, or the copy job is denied at the vault."
  }
}

run "vault_policy_denies_deletion_of_recovery_points" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.vault_policy).Statement :
      s.Effect == "Deny" && contains(s.Action, "backup:DeleteRecoveryPoint")
    ])
    error_message = "The deny-delete statement should cover recovery point deletion."
  }
}

# The defect this asserts against: denying these two actions with Principal "*"
# and no exemption makes the policy unmodifiable and unremovable by the very
# role that created it. The vault could then never gain a new source account or
# a break-glass exemption, and `terraform destroy` could never succeed. A policy
# that cannot be corrected is a lockout, not a control. Vault Lock is what
# provides the tamper-proof guarantee.
run "vault_policy_does_not_deny_its_own_replacement" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.vault_policy).Statement :
      s.Effect != "Deny" || !contains(s.Action, "backup:PutBackupVaultAccessPolicy")
    ])
    error_message = "Denying PutBackupVaultAccessPolicy to every principal locks the account out of its own vault policy permanently."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(local.vault_policy).Statement :
      s.Effect != "Deny" || !contains(s.Action, "backup:DeleteBackupVaultAccessPolicy")
    ])
    error_message = "Denying DeleteBackupVaultAccessPolicy to every principal makes terraform destroy impossible."
  }
}

run "break_glass_principals_are_exempt_from_the_deny" {
  command = apply

  variables {
    deny_delete_principals_except = ["arn:aws:iam::111111111111:role/break-glass"]
  }

  assert {
    condition = anytrue([
      for s in jsondecode(local.vault_policy).Statement :
      s.Effect == "Deny" &&
      try(contains(s.Condition.ArnNotLike["aws:PrincipalArn"], "arn:aws:iam::111111111111:role/break-glass"), false)
    ])
    error_message = "An exempt principal must appear in the deny statement's ArnNotLike condition."
  }
}

run "no_deny_statement_when_the_policy_is_disabled" {
  command = apply

  variables {
    enable_deny_delete_policy = false
  }

  assert {
    condition = alltrue([
      for s in jsondecode(local.vault_policy).Statement : s.Effect != "Deny"
    ])
    error_message = "Disabling the deny-delete policy should leave only the cross-account allow."
  }
}

# --------------------------------------------------------------------------
# KMS key policy
#
# The half of the cross-account path that is most often missed. Granting the
# vault policy without the key policy produces a copy job that fails with
# AccessDenied on the destination key, nightly, after a clean apply.
# --------------------------------------------------------------------------

run "key_policy_delegates_to_the_owning_account" {
  command = apply

  # Without this KMS rejects the policy outright, and no IAM policy in the
  # account could grant access to the key.
  assert {
    condition = anytrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Effect == "Allow" && s.Action == "kms:*" &&
      s.Principal.AWS == "arn:aws:iam::111111111111:root"
    ])
    error_message = "The key policy must delegate to the owning account or the key is unmanageable."
  }
}

run "key_policy_lets_the_source_account_re_encrypt_the_copy" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Sid == "AllowSourceAccountsToCopyIn" &&
      contains(s.Action, "kms:GenerateDataKey") &&
      contains(s.Action, "kms:Decrypt")
    ])
    error_message = "The source account must be able to use the destination key, or every encrypted cross-account copy fails with AccessDenied."
  }
}

# The grant above is the one place this module hands data-plane access to
# another account. Unconditional, it would give anyone with admin in the source
# account the ability to read everything in the isolated vault, which is the
# exact failure the account boundary exists to prevent.
#
# But the scoping must not fail CLOSED. AWS Backup may authorise its copy-time
# KMS calls through a grant rather than through this statement, in which case
# kms:ViaService is absent from the request, and a plain StringEquals on an
# absent context key evaluates FALSE, denying the very operation the statement
# exists to permit. Silently, nightly, after a clean apply.
#
# So: IfExists, and a wildcard Region (a cross-account destination may also be
# cross-Region, and pinning the destination Region would not match a call made
# from the source Region's endpoint). The narrowing that does NOT depend on a
# context key being present is naming the source role, below.
run "the_cross_account_grant_is_scoped_to_aws_backup_without_failing_closed" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Sid != "AllowSourceAccountsToCopyIn" ||
      try(s.Condition.StringLikeIfExists["kms:ViaService"], null) == "backup.*.amazonaws.com"
    ])
    error_message = "The cross-account key grant should be scoped to AWS Backup with an IfExists condition and a wildcard Region."
  }

  # The same rule the neighbouring service statement follows. Asserting one
  # convention here and the opposite there is how a suite enshrines a
  # contradiction.
  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Sid != "AllowSourceAccountsToCopyIn" || try(s.Condition.StringEquals, null) == null
    ])
    error_message = "A plain StringEquals here would deny the copy whenever the context key is absent."
  }
}

run "the_cross_account_grant_can_be_narrowed_to_the_source_role" {
  command = apply

  variables {
    source_principal_arns = ["arn:aws:iam::111111111111:role/platform-backup-service-role"]
  }

  # Naming the role is the only narrowing here that cannot be defeated by an
  # absent context key.
  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      !startswith(s.Sid, "AllowSourceAccounts") ||
      contains(tolist(s.Principal.AWS), "arn:aws:iam::111111111111:role/platform-backup-service-role")
    ])
    error_message = "source_principal_arns should replace the account root as the cross-account principal."
  }

  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      !startswith(s.Sid, "AllowSourceAccounts") ||
      !contains(tolist(s.Principal.AWS), "arn:aws:iam::111111111111:root")
    ])
    error_message = "Narrowing to a role should drop the account-root principal, not add to it."
  }
}

run "cross_account_create_grant_is_limited_to_aws_resources" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Sid != "AllowSourceAccountsToGrantForAWSResources" ||
      try(s.Condition.Bool["kms:GrantIsForAWSResource"], null) == "true"
    ])
    error_message = "An unconditional kms:CreateGrant lets the source account mint persistent access to the isolated key."
  }
}

run "no_cross_account_statements_without_source_accounts" {
  command = apply

  variables {
    source_account_ids = []
  }

  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      !startswith(s.Sid, "AllowSourceAccounts")
    ])
    error_message = "A vault with no declared source accounts should grant no external account anything."
  }
}

run "backup_service_conditions_use_ifexists" {
  command = apply

  # A plain StringEquals on a context key the caller does not populate evaluates
  # FALSE and denies the request. On the service statement that would break
  # copies; on the assume-role trust policy in the parent module it would stop
  # every backup job in the account, silently.
  assert {
    condition = alltrue([
      for s in jsondecode(local.kms_policy).Statement :
      s.Sid != "AllowAWSBackupService" ||
      try(s.Condition.StringEqualsIfExists, null) != null
    ])
    error_message = "Confused-deputy conditions on a service principal should use IfExists so an absent context key does not deny the call."
  }
}
