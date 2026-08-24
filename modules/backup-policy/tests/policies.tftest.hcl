# The IAM and SNS policies this module renders, asserted on their content.
#
# Built with jsonencode rather than aws_iam_policy_document so that a mocked
# provider can still see them: a data source cannot be computed under mocks, so
# a policy built that way renders as an empty placeholder and goes untested.
# These policies decide whether a copy job succeeds or fails with AccessDenied
# at 02:00, which is not something to leave unverified.

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

# --------------------------------------------------------------------------
# The service role's trust policy
# --------------------------------------------------------------------------

run "trust_policy_allows_only_aws_backup" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.backup_assume_role_policy).Statement :
      s.Principal.Service == "backup.amazonaws.com"
    ])
    error_message = "Only the AWS Backup service should be able to assume the backup role."
  }
}

# A plain StringEquals on a context key the caller does not populate evaluates
# to FALSE and denies the request. On an assume-role trust policy that means the
# role is unassumable and NO backup job in the account ever runs, with nothing
# failing at apply time to indicate it. AWS's own generated service role carries
# no conditions at all; IfExists keeps the confused-deputy protection where the
# keys are present without betting the whole policy on them always being so.
run "trust_policy_conditions_do_not_fail_closed_on_an_absent_key" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.backup_assume_role_policy).Statement :
      try(s.Condition.StringEquals, null) == null && try(s.Condition.ArnLike, null) == null
    ])
    error_message = "Use StringEqualsIfExists/ArnLikeIfExists: a plain condition on an absent context key makes the role unassumable and stops every backup job in the account."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(local.backup_assume_role_policy).Statement :
      try(s.Condition.StringEqualsIfExists["aws:SourceAccount"], null) == "111111111111"
    ])
    error_message = "The confused-deputy guard on aws:SourceAccount should still be present."
  }
}

# --------------------------------------------------------------------------
# The copy-and-encrypt inline policy
#
# The full cross-account permission path is four grants, and all four must be
# present or the copy fails:
#   1. source role  -> backup:CopyIntoBackupVault on the destination vault   (here)
#   2. source role  -> kms:* data plane on the destination KEY               (here)
#   3. destination vault policy -> the source account                       (backup-vault)
#   4. destination key policy   -> the source account                       (backup-vault)
# Grant 2 is the one that is easy to miss, because grant 4 looks like it should
# be enough, but a key policy naming <account>:root only DELEGATES to that
# account's IAM; it authorises nothing on its own.
# --------------------------------------------------------------------------

run "role_can_copy_into_every_destination_vault" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.backup_copy_policy).Statement :
      s.Sid == "CopyIntoDestinationVaults" &&
      contains(s.Resource, "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso")
    ])
    error_message = "The role must be allowed to copy into the external destination vault."
  }
}

run "role_can_use_the_external_destinations_key" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.backup_copy_policy).Statement :
      s.Sid == "UseVaultKeys" &&
      contains(s.Resource, "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333")
    ])
    error_message = "Without an IAM allow on the DESTINATION key, every encrypted cross-account copy fails with AccessDenied, nightly, after a clean apply."
  }
}

run "create_grant_is_limited_to_aws_resources" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(local.backup_copy_policy).Statement :
      s.Sid != "GrantOnVaultKeysForAWSResources" ||
      try(s.Condition.Bool["kms:GrantIsForAWSResource"], null) == "true"
    ])
    error_message = "kms:CreateGrant must be conditioned on GrantIsForAWSResource."
  }
}

run "key_permissions_are_scoped_to_the_vault_keys" {
  command = apply

  # A wildcard here would let the backup role decrypt every key in the account.
  #
  # Resource is a list on some statements and a string on others, so a bare
  # `!= "*"` is vacuously true for the list ones. Normalising with flatten()
  # makes the assertion cover every statement rather than only the string case.
  assert {
    condition = alltrue(flatten([
      for s in jsondecode(local.backup_copy_policy).Statement :
      [for r in flatten([s.Resource]) : r != "*"]
    ]))
    error_message = "No statement should grant on all resources; the role's KMS access is scoped to the vault keys."
  }
}

# --------------------------------------------------------------------------
# Notification topic encryption
#
# alias/aws/sns is the AWS-MANAGED key. Its policy grants only this account's
# IAM principals via kms:ViaService and cannot be edited, so AWS Backup,
# EventBridge and CloudWatch cannot obtain kms:GenerateDataKey* on it and every
# publish fails with KMSAccessDeniedException, at delivery time, invisibly.
# That would silence the staleness alarm in particular, which is the one control
# that detects a plan that has stopped running at all.
# --------------------------------------------------------------------------

run "topics_are_not_encrypted_with_the_aws_managed_key" {
  command = apply

  assert {
    condition = alltrue([
      for k, t in aws_sns_topic.backup : t.kms_master_key_id != "alias/aws/sns"
    ])
    error_message = "alias/aws/sns cannot be published to by AWS service principals; every notification would fail at delivery time, with nothing to show for it."
  }
}

run "the_topic_policy_denies_plaintext_publishes" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.sns_topic_policy["eu-central-1"]).Statement :
      s.Effect == "Deny" && try(s.Condition.Bool["aws:SecureTransport"], null) == "false"
    ])
    error_message = "The topic should refuse publishes over plaintext HTTP."
  }
}

run "the_topic_policy_keeps_the_owner_grant_sns_would_otherwise_provide" {
  command = apply

  # Replacing the topic policy removes SNS's auto-generated
  # __default_statement_ID. Same-account access survives through IAM, but
  # console and subscription management behave surprisingly without it.
  assert {
    condition = anytrue([
      for s in jsondecode(local.sns_topic_policy["eu-central-1"]).Statement :
      s.Sid == "AllowTopicOwner" &&
      try(s.Principal.AWS, null) == "arn:aws:iam::111111111111:root"
    ])
    error_message = "The topic owner grant should be restated, not dropped, when the default policy is replaced."
  }
}

run "the_sns_key_policy_grants_every_publishing_service" {
  command = apply

  assert {
    condition = alltrue([
      for svc in ["backup.amazonaws.com", "events.amazonaws.com", "cloudwatch.amazonaws.com"] :
      anytrue([
        for s in jsondecode(local.sns_key_policy).Statement :
        try(contains(s.Principal.Service, svc), false) && contains(s.Action, "kms:GenerateDataKey")
      ])
    ])
    error_message = "Vault notifications, the EventBridge rule and the CloudWatch alarms all publish to these topics; each principal needs GenerateDataKey on the key."
  }
}

run "the_topic_policy_grants_every_publishing_service" {
  command = apply

  # The topic policy and the key policy gate the same publish, so they have to
  # agree about whether an absent aws:SourceAccount denies it. A plain
  # StringEquals on the topic while the key uses IfExists means the carefully
  # written half is wasted and the message is dropped anyway.
  assert {
    condition = alltrue([
      for s in jsondecode(local.sns_topic_policy["eu-central-1"]).Statement :
      try(s.Principal.Service, null) == null || try(s.Condition.StringEquals, null) == null
    ])
    error_message = "The topic policy's service conditions must use IfExists, matching the KMS key policy that gates the same publish."
  }

  assert {
    condition = alltrue([
      for svc in ["backup.amazonaws.com", "events.amazonaws.com", "cloudwatch.amazonaws.com"] :
      anytrue([
        for s in jsondecode(local.sns_topic_policy["eu-central-1"]).Statement :
        try(s.Principal.Service, null) == svc && s.Action == "SNS:Publish"
      ])
    ])
    error_message = "Each publishing service needs SNS:Publish on the topic as well as KMS on its key."
  }
}
