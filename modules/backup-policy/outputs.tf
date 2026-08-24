output "plan_id" {
  description = "ID of the backup plan."
  value       = aws_backup_plan.this.id
}

output "plan_arn" {
  description = "ARN of the backup plan."
  value       = aws_backup_plan.this.arn
}

output "plan_version" {
  description = "Version ID of the backup plan. Changes on every plan modification; useful for change evidence."
  value       = aws_backup_plan.this.version
}

output "selection_id" {
  description = "ID of the tag-based backup selection."
  value       = aws_backup_selection.this.id
}

output "backup_role_arn" {
  description = "ARN of the AWS Backup service role in use."
  value       = local.backup_role_arn
}

output "primary_vault" {
  description = "The vault every backup job writes to first."
  value = {
    name        = module.primary_vault.name
    arn         = module.primary_vault.arn
    region      = local.primary_region
    kms_key_arn = module.primary_vault.kms_key_arn
    lock        = module.primary_vault.lock
  }
}

output "copy_vaults" {
  description = "Vaults created by this module as copy destinations, keyed by their logical destination name."
  value = {
    for k, m in module.copy_vault : k => {
      name        = m.name
      arn         = m.arn
      region      = m.region
      kms_key_arn = m.kms_key_arn
      lock        = m.lock
    }
  }
}

output "destination_vault_arns" {
  description = "Every copy destination ARN, managed and external, keyed by logical name."
  value       = local.destination_vault_arns
}

output "notification_topic_arns" {
  description = "SNS topic ARNs by Region. Subscribe an on-call channel to the primary-Region topic."
  value       = { for k, t in aws_sns_topic.backup : k => t.arn }
}

output "restore_testing_plan_names" {
  description = "Restore testing plan names by Region. One per Region, because restore testing cannot select a vault in another Region."
  value       = { for k, p in aws_backup_restore_testing_plan.this : k => p.name }
}

output "unchecked_copy_destinations" {
  description = <<-EOT
    External copy destinations whose Vault Lock retention window was not declared, and whose
    retention therefore could not be validated at plan time.

    Always empty unless `acknowledge_unchecked_copy_destinations` is true, because otherwise
    the plan refuses. Surfaced so the gap in the module's headline guarantee stays visible.
  EOT
  value       = local.unchecked_copy_destinations_out
}

output "unvalidated_retention_targets" {
  description = <<-EOT
    Everything whose retention this module did NOT validate, and why. Covers the primary
    vault as well as the copy destinations: a disabled lock on the vault every backup job
    writes to first should not be the one omission nobody sees.

    Two distinct reasons appear here, and only the second is a gap rather than a choice:

      "(lock disabled)"                     the operator turned the lock off, so there is no
                                            window to check. A stated intent.
      "(external, lock window not declared)" the Vault Lock lives in another account and this
                                            module cannot read it. Genuinely unvalidated, and
                                            refused at plan time unless acknowledged.
  EOT
  value       = local.unvalidated_retention_targets
}

output "audit_framework_arn" {
  description = "ARN of the Audit Manager framework, or null when disabled."
  value       = var.enable_audit_framework ? aws_backup_framework.this[0].arn : null
}

output "effective_copy_matrix" {
  description = <<-EOT
    Which rule copies where, with the retention applied at each hop. Rendered as a plain map so
    it can be diffed in review and pasted into a change record, the copy topology is the part
    of a backup policy most likely to be misread from the Terraform alone.
  EOT
  value = {
    for r in var.rules : r.name => {
      schedule       = r.schedule
      local_days     = r.retention.delete_after
      cold_after     = r.retention.cold_storage_after
      copies_to      = { for c in local.copy_actions[r.name] : c.destination => c.lifecycle_config.delete_after }
      continuous_pit = r.enable_continuous_backup
    }
  }
}
