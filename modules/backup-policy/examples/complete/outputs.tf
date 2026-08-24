output "plan_arn" {
  description = "ARN of the backup plan."
  value       = module.backup_policy.plan_arn
}

output "vaults" {
  description = "Every vault in the topology, with its Region, key and lock state."
  value = {
    primary        = module.backup_policy.primary_vault
    copies         = module.backup_policy.copy_vaults
    backup_account = { name = module.backup_account_vault.name, arn = module.backup_account_vault.arn, lock = module.backup_account_vault.lock }
  }
}

output "copy_matrix" {
  description = "Which tier copies where, and with what retention at each hop. Worth pasting into the change record."
  value       = module.backup_policy.effective_copy_matrix
}

output "notification_topic_arns" {
  description = "SNS topics by Region."
  value       = module.backup_policy.notification_topic_arns
}
