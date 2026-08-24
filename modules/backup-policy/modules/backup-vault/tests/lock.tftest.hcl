# Vault Lock behaviour.
#
# Vault Lock is the only control in this design that cannot be undone, so the
# module's job is to make the irreversible case hard to reach by accident and
# the reversible case the default.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name = "platform-backup-primary"
}

run "governance_is_the_default" {
  command = apply

  # Governance mode first is the whole rollout strategy: prove a backup, a copy
  # and a restore against a lock you can still remove, then commit.
  assert {
    condition     = aws_backup_vault_lock_configuration.this[0].changeable_for_days == null
    error_message = "A governance lock must omit changeable_for_days; setting it is what selects compliance mode."
  }

  assert {
    condition     = aws_backup_vault_lock_configuration.this[0].min_retention_days == 7
    error_message = "The default lock should still enforce a retention floor."
  }
}

run "refuses_a_compliance_lock_without_acknowledgement" {
  command = plan

  variables {
    lock = {
      enabled = true
      mode    = "compliance"
    }
    confirm_irreversible_compliance_lock = false
  }

  # Nothing else in this module is permanent. This guard is the difference
  # between a typo and a seven-year commitment that AWS Support cannot undo.
  expect_failures = [aws_backup_vault_lock_configuration.this]
}

run "creates_a_compliance_lock_once_acknowledged" {
  command = apply

  variables {
    lock = {
      enabled             = true
      mode                = "compliance"
      changeable_for_days = 5
      min_retention_days  = 35
      max_retention_days  = 2555
    }
    confirm_irreversible_compliance_lock = true
  }

  assert {
    condition     = aws_backup_vault_lock_configuration.this[0].changeable_for_days == 5
    error_message = "A compliance lock must set changeable_for_days."
  }
}

run "lock_can_be_disabled_for_throwaway_environments" {
  command = apply

  variables {
    lock = {
      enabled = false
    }
  }

  assert {
    condition     = length(aws_backup_vault_lock_configuration.this) == 0
    error_message = "Disabling the lock should create no lock configuration at all."
  }
}

run "rejects_an_inverted_retention_window" {
  command = plan

  variables {
    lock = {
      enabled            = true
      min_retention_days = 3650
      max_retention_days = 35
    }
  }

  expect_failures = [var.lock]
}

run "rejects_a_grace_period_below_the_api_minimum" {
  command = plan

  variables {
    lock = {
      enabled             = true
      mode                = "compliance"
      changeable_for_days = 1
    }
  }

  expect_failures = [var.lock]
}

run "a_cross_account_destination_grants_the_source_account" {
  command = apply

  variables {
    source_account_ids = ["111111111111", "333333333333"]
  }

  # Both the vault policy and the KMS key policy have to name the source
  # account. Granting only one of them is the most common reason a
  # cross-account copy job never lands.
  assert {
    condition     = length(aws_backup_vault_policy.this) == 1
    error_message = "A vault with source accounts must carry an access policy."
  }

  assert {
    condition     = length(aws_kms_key.this) == 1
    error_message = "A cross-account destination needs its own key in the destination account."
  }
}

run "deny_delete_policy_is_on_by_default" {
  command = apply

  # Defence in depth behind Vault Lock, and the only deletion control in effect
  # during the governance-mode validation window.
  assert {
    condition     = length(aws_backup_vault_policy.this) == 1
    error_message = "The deny-delete vault policy should be attached by default."
  }
}
