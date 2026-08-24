variable "name" {
  description = "Name of the backup vault. Must be unique within the account and Region."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{2,50}$", var.name))
    error_message = "Vault names may contain only letters, numbers, hyphens and underscores (2-50 characters)."
  }
}

variable "region" {
  description = <<-EOT
    Region to create the vault in. Defaults to the provider's Region when null.

    Set this to place the vault in a Region other than the provider's without
    declaring a provider alias. Cross-ACCOUNT placement still requires an aliased
    provider, because it needs different credentials.
  EOT
  type        = string
  default     = null
}

variable "create_kms_key" {
  description = "Create a dedicated customer managed key for this vault. When false, kms_key_arn must be supplied."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of an existing KMS key to encrypt the vault with. Required when create_kms_key is false."
  type        = string
  default     = null
}

variable "kms_deletion_window_in_days" {
  description = "Waiting period before a scheduled deletion of a module-created KMS key completes."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window_in_days >= 7 && var.kms_deletion_window_in_days <= 30
    error_message = "kms_deletion_window_in_days must be between 7 and 30."
  }
}

variable "kms_enable_key_rotation" {
  description = "Enable automatic annual rotation on module-created KMS keys."
  type        = bool
  default     = true
}

variable "source_account_ids" {
  description = <<-EOT
    Account IDs allowed to copy recovery points INTO this vault, and to use its KMS key
    to do so. Leave empty for a vault that only receives backups from its own account.

    Populating this is what makes a vault a valid cross-account copy destination: the
    destination vault policy and the destination KMS key policy both have to grant the
    source account, in addition to the Organizations-level cross-account backup opt-in.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.source_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "Each entry in source_account_ids must be a 12-digit AWS account ID."
  }
}

variable "lock" {
  description = <<-EOT
    Vault Lock (WORM) configuration.

      enabled              Create a lock at all. Leave true for anything that matters.
      mode                 "governance" or "compliance".
                           governance  - removable by a principal holding backup:DeleteBackupVaultLockConfiguration.
                                         Useful while validating a new plan end to end.
                           compliance  - irreversible once changeable_for_days elapses. No principal, including
                                         the account root and AWS Support, can shorten retention or delete a
                                         recovery point before its lifecycle completes. This is the only mode
                                         that survives an attacker holding administrator credentials, which is
                                         the entire reason a separate backup account exists.
      changeable_for_days  Grace period for a compliance lock. Minimum 3. Ignored in governance mode.
      min_retention_days   Rejects any incoming backup or copy job whose delete_after is shorter.
      max_retention_days   Rejects any incoming backup or copy job whose delete_after is longer.

    min/max are enforced by AWS Backup on every job, not at apply time. A plan whose retention
    falls outside this window applies cleanly and then fails every night in production. The
    parent module cross-checks the two at plan time for exactly that reason.
  EOT

  type = object({
    enabled             = optional(bool, true)
    mode                = optional(string, "governance")
    changeable_for_days = optional(number, 3)
    min_retention_days  = optional(number, 7)
    max_retention_days  = optional(number, 3650)
  })
  default = {}

  validation {
    condition     = contains(["governance", "compliance"], var.lock.mode)
    error_message = "lock.mode must be \"governance\" or \"compliance\"."
  }

  validation {
    condition     = var.lock.changeable_for_days >= 3 && var.lock.changeable_for_days <= 36500
    error_message = "lock.changeable_for_days must be between 3 and 36500."
  }

  validation {
    condition     = var.lock.min_retention_days >= 1 && var.lock.min_retention_days <= 36500
    error_message = "lock.min_retention_days must be between 1 and 36500."
  }

  validation {
    condition     = var.lock.max_retention_days >= 1 && var.lock.max_retention_days <= 36500
    error_message = "lock.max_retention_days must be between 1 and 36500."
  }

  validation {
    condition     = var.lock.max_retention_days >= var.lock.min_retention_days
    error_message = "lock.max_retention_days must be greater than or equal to lock.min_retention_days."
  }
}

variable "confirm_irreversible_compliance_lock" {
  description = <<-EOT
    Explicit acknowledgement required before a COMPLIANCE lock is created.

    This is a deliberate speed bump, not ceremony. A compliance lock cannot be undone by
    anyone; `terraform destroy` will fail while the vault holds recovery points; and a
    mistaken min_retention_days becomes a financial commitment for its full duration.
    The documented rollout is: apply in governance mode, prove a full backup -> copy ->
    restore cycle, then set this to true and switch the mode.
  EOT
  type        = bool
  default     = false
}

variable "deny_delete_principals_except" {
  description = <<-EOT
    Principal ARNs exempt from the vault policy statement that denies recovery-point and
    vault deletion. Typically a break-glass role. Empty denies every principal.

    This is defence in depth behind Vault Lock, and the only deletion control in effect
    during the governance-mode validation window.
  EOT
  type        = list(string)
  default     = []
}

variable "enable_deny_delete_policy" {
  description = "Attach a vault access policy that denies deletion APIs. Independent of Vault Lock."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = <<-EOT
    Allow `terraform destroy` to delete the vault along with the recovery points it holds.

    False everywhere that matters. Useful for a throwaway sandbox, and irrelevant once a
    compliance-mode lock is committed -- that lock refuses the deletion regardless of this
    setting, which is the point of it.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to the vault and to any module-created KMS key."
  type        = map(string)
  default     = {}
}
