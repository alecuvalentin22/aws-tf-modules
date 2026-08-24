###############################################################################
# Vaults
#
# The primary vault plus one vault per managed copy destination. All of them are
# instances of the same child module, so the KMS key policy, the Vault Lock, the
# deny-delete policy and the notification wiring are defined once and cannot
# drift between locations.
#
# `for_each` over copy destinations is possible because the AWS provider's
# per-resource `region` argument decouples "which Region" from "which provider".
# Adding a third or fourth Region is a map entry, not a new provider alias and a
# new copy of every resource.
###############################################################################

module "primary_vault" {
  source = "./modules/backup-vault"

  name                                 = local.primary_vault_name
  region                               = var.primary_vault.region
  create_kms_key                       = var.primary_vault.create_kms_key
  kms_key_arn                          = var.primary_vault.kms_key_arn
  kms_deletion_window_in_days          = var.primary_vault.kms_deletion_window_in_days
  lock                                 = var.primary_vault.lock
  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  enable_deny_delete_policy     = var.enable_deny_delete_policy
  deny_delete_principals_except = var.deny_delete_principals_except
  force_destroy                 = var.vault_force_destroy

  tags = local.tags
}

module "copy_vault" {
  source   = "./modules/backup-vault"
  for_each = local.managed_destinations

  name                                 = coalesce(each.value.name, "${var.name}-${each.key}")
  region                               = each.value.region
  create_kms_key                       = coalesce(each.value.create_kms_key, true)
  kms_key_arn                          = each.value.kms_key_arn
  kms_deletion_window_in_days          = coalesce(each.value.kms_deletion_window_in_days, 30)
  lock                                 = each.value.lock
  confirm_irreversible_compliance_lock = var.confirm_irreversible_compliance_lock

  enable_deny_delete_policy     = var.enable_deny_delete_policy
  deny_delete_principals_except = var.deny_delete_principals_except
  force_destroy                 = var.vault_force_destroy

  tags = merge(local.tags, { CopyDestination = each.key })
}

###############################################################################
# Account- and Region-level settings.
#
# Both are singletons. Owning them from a module that may be instantiated more
# than once is a way to make two Terraform states revert each other on every
# apply, so both are opt-in and documented as such.
###############################################################################

resource "aws_backup_region_settings" "this" {
  for_each = var.opt_in_resource_types == null ? toset([]) : toset(local.managed_regions)

  region                          = each.key
  resource_type_opt_in_preference = var.opt_in_resource_types
}

resource "aws_backup_global_settings" "this" {
  count = var.enable_cross_account_backup_global_setting ? 1 : 0

  global_settings = {
    isCrossAccountBackupEnabled = "true"
  }
}
