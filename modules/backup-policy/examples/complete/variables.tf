variable "name" {
  description = "Base name for the backup policy and its resources."
  type        = string
  default     = "platform-backup"
}

variable "primary_region" {
  description = "Region hosting the plan and the primary vault."
  type        = string
  default     = "eu-central-1"
}

variable "secondary_region" {
  description = "Region receiving the cross-Region copy."
  type        = string
  default     = "eu-west-1"
}

variable "backup_account_role_arn" {
  description = "Role in the isolated backup account that Terraform assumes to create the destination vault."
  type        = string
}

variable "vault_lock_mode" {
  description = <<-EOT
    "governance" while validating, "compliance" once a full backup -> copy -> restore cycle
    has been proven. Compliance mode cannot be undone; see docs/adr/0001.
  EOT
  type        = string
  default     = "governance"
}

variable "confirm_irreversible_compliance_lock" {
  description = "Must be true before any COMPLIANCE lock is created. Left false so a copy-paste of this example cannot create one by accident."
  type        = bool
  default     = false
}

variable "owner_tag_pattern" {
  description = "Wildcard the Owner tag must match. Enforces that an owner exists and is a corporate address, without pinning a single mailbox."
  type        = string
  default     = "*@example.com"
}

variable "break_glass_role_arns" {
  description = "Roles exempt from the deny-delete vault policy. Not exempt from Vault Lock, nothing is."
  type        = list(string)
  default     = []
}

variable "notification_subscriptions" {
  description = "protocol => endpoint subscribed to the primary-Region SNS topic."
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags applied to everything created here."
  type        = map(string)
  default = {
    Service = "platform-backup"
  }
}
