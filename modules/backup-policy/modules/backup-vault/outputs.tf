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
