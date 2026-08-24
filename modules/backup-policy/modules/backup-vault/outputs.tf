output "name" {
  description = "Name of the backup vault."
  value       = aws_backup_vault.this.name
}

output "arn" {
  description = "ARN of the backup vault. This is what a copy_action targets."
  value       = aws_backup_vault.this.arn
}

output "region" {
  description = "Region the vault was created in."
  value       = var.region
}

output "kms_key_arn" {
  description = "ARN of the KMS key encrypting the vault."
  value       = local.kms_key_arn
}

output "lock" {
  description = "Effective Vault Lock settings, including the retention window jobs are validated against."
  value = {
    enabled            = var.lock.enabled
    mode               = var.lock.enabled ? var.lock.mode : null
    min_retention_days = var.lock.enabled ? var.lock.min_retention_days : null
    max_retention_days = var.lock.enabled ? var.lock.max_retention_days : null
  }
}

output "kms_key_policy_json" {
  description = <<-EOT
    The rendered KMS key policy. Exposed so it can be asserted on in `terraform test` and
    diffed in review: this policy is what permits (or blocks) a
    cross-account copy, and it is not visible in a plan diff in any readable form.
  EOT
  value       = var.create_kms_key ? local.kms_policy : null
}

output "vault_policy_json" {
  description = "The rendered vault access policy, or null when none is attached. Exposed for the same reason as the key policy."
  value       = local.create_vault_policy ? local.vault_policy : null
}
