###############################################################################
# Identity
###############################################################################

variable "name" {
  description = "Base name for every resource this module creates."
  type        = string
  default     = "platform-backup"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,29}$", var.name))
    error_message = "name must be 2-30 characters of lowercase letters, digits and hyphens, starting with a letter or digit."
  }
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}

###############################################################################
# PLAN DEFINITION, frequency, retention, encryption
###############################################################################

variable "rules" {
  description = <<-EOT
    The tiers of the backup plan. One rule per frequency/retention combination.

      name                     Rule name, unique within the plan.
      schedule                 cron(...) or rate(...). This is the backup FREQUENCY.
      schedule_timezone        IANA zone the schedule is evaluated in. Defaults to Etc/UTC.
      start_window_minutes     How long a job may wait for a start slot before being marked missed.
      completion_window_minutes Hard deadline for the job once started.
      enable_continuous_backup Point-in-time recovery. Constrains retention (see validations).
      recovery_point_tags      Extra tags stamped on recovery points created by this rule.

      retention                Lifecycle of the recovery point in the LOCAL vault.
        delete_after           Days to keep. This is the backup RETENTION.
        cold_storage_after     Days before transition to cold storage. AWS requires
                               delete_after >= cold_storage_after + 90.
        opt_in_to_archive_for_supported_resources
                               Use the archive tier where the resource type supports it.

      copy_to                  Logical destinations this rule copies to. Each entry must be a
                               key of `copy_destinations`. A copy action inherits its rule's
                               schedule, AWS Backup has no independent copy frequency, so a
                               different copy cadence is expressed as a different rule.

      copy_retention           Per-destination lifecycle override, keyed by destination. Any
                               destination not named here inherits `retention`.

    Copy cost is the reason `copy_to` is per-rule rather than per-plan: copying every daily
    point to a second account triples storage for the tier that is least likely to be the one
    restored from. The default below copies dailies cross-Region only, and sends the weekly and
    monthly tiers to the isolated account as well.
  EOT

  type = list(object({
    name                      = string
    schedule                  = string
    schedule_timezone         = optional(string, "Etc/UTC")
    start_window_minutes      = optional(number, 60)
    completion_window_minutes = optional(number, 720)
    enable_continuous_backup  = optional(bool, false)
    recovery_point_tags       = optional(map(string), {})

    # See the validation below.
    acknowledge_continuous_backup_copy = optional(bool, false)

    retention = object({
      delete_after                              = number
      cold_storage_after                        = optional(number)
      opt_in_to_archive_for_supported_resources = optional(bool, false)
    })

    copy_to = optional(list(string), [])

    # Attributes are optional with NO default, so an unset field stays null and
    # is distinguishable from an explicit false. That is what lets an override
    # be merged field by field over `retention` instead of replacing it
    # wholesale, a partial override that silently dropped cold_storage_after
    # would keep a seven-year copy in warm storage.
    copy_retention = optional(map(object({
      delete_after       = optional(number)
      cold_storage_after = optional(number)

      # Merging field by field means null has to mean "inherit", which leaves no
      # way to say "no cold tier on this hop". This is that sentinel. Without it a
      # short WARM operational copy of a rule that tiers to cold is inexpressible
      #, and worse, it inherits a cold transition that makes restores take hours.
      disable_cold_storage                      = optional(bool, false)
      opt_in_to_archive_for_supported_resources = optional(bool)
    })), {})
  }))

  default = [
    {
      name              = "daily"
      schedule          = "cron(0 2 * * ? *)"
      schedule_timezone = "Etc/UTC"
      retention         = { delete_after = 35 }
      copy_to           = ["secondary_region"]
    },
    {
      name              = "weekly"
      schedule          = "cron(0 3 ? * SUN *)"
      schedule_timezone = "Etc/UTC"
      retention         = { delete_after = 90 }
      copy_to           = ["secondary_region", "backup_account"]
    },
    {
      name                      = "monthly"
      schedule                  = "cron(0 4 1 * ? *)"
      schedule_timezone         = "Etc/UTC"
      completion_window_minutes = 1440
      retention = {
        delete_after       = 2555
        cold_storage_after = 90
      }
      copy_to = ["secondary_region", "backup_account"]
    },
  ]

  validation {
    condition     = length(var.rules) > 0
    error_message = "At least one rule is required; a plan with no rules backs nothing up."
  }

  validation {
    condition     = length(distinct([for r in var.rules : r.name])) == length(var.rules)
    error_message = "Rule names must be unique within a plan."
  }

  validation {
    condition = alltrue([
      for r in var.rules : can(regex("^[A-Za-z0-9_.-]{1,50}$", r.name))
    ])
    error_message = "Rule names may contain only letters, digits, hyphens, underscores and dots (max 50 characters)."
  }

  validation {
    condition = alltrue([
      for r in var.rules : can(regex("^(cron|rate)\\(.+\\)$", r.schedule))
    ])
    error_message = "Each rule.schedule must be a cron(...) or rate(...) expression."
  }

  # AWS Backup rejects a lifecycle whose cold-storage transition is less than 90 days
  # before expiry, because the archive tier has a 90-day minimum charge.
  #
  # Checked against the EFFECTIVE lifecycle of each copy, the override merged
  # field by field over the rule's own retention, because that is what AWS
  # will actually be asked to apply. Validating the override in isolation would
  # miss a partial override that inherits an incompatible cold_storage_after.
  validation {
    condition = alltrue(flatten([
      for r in var.rules : concat(
        [
          r.retention.cold_storage_after == null ||
          r.retention.delete_after >= r.retention.cold_storage_after + 90
        ],
        [
          for c in values(r.copy_retention) :
          c.disable_cold_storage ||
          (c.cold_storage_after != null ? c.cold_storage_after : r.retention.cold_storage_after) == null ||
          coalesce(c.delete_after, r.retention.delete_after) >=
          (c.cold_storage_after != null ? c.cold_storage_after : r.retention.cold_storage_after) + 90
        ],
      )
    ]))
    error_message = "delete_after must be at least 90 days after cold_storage_after, for the rule lifecycle and for every copy destination's effective lifecycle."
  }

  validation {
    condition = alltrue(flatten([
      for r in var.rules : concat(
        [r.retention.delete_after >= 1],
        [for c in values(r.copy_retention) : coalesce(c.delete_after, r.retention.delete_after) >= 1],
      )
    ]))
    error_message = "Every delete_after must be at least 1 day."
  }

  # Continuous backup keeps a rolling PITR window; AWS caps it at 35 days and it
  # cannot be tiered to cold storage.
  validation {
    condition = alltrue([
      for r in var.rules :
      !r.enable_continuous_backup || (r.retention.delete_after <= 35 && r.retention.cold_storage_after == null)
    ])
    error_message = "A rule with enable_continuous_backup must use delete_after <= 35 and must not set cold_storage_after."
  }

  validation {
    condition = alltrue(flatten([
      for r in var.rules : concat(
        [
          !r.retention.opt_in_to_archive_for_supported_resources ||
          r.retention.cold_storage_after != null
        ],
        [
          for c in values(r.copy_retention) :
          !(c.opt_in_to_archive_for_supported_resources != null
            ? c.opt_in_to_archive_for_supported_resources
          : r.retention.opt_in_to_archive_for_supported_resources) ||
          (!c.disable_cold_storage &&
          (c.cold_storage_after != null ? c.cold_storage_after : r.retention.cold_storage_after) != null)
        ],
      )
    ]))
    error_message = "opt_in_to_archive_for_supported_resources requires cold_storage_after to be set on the same effective lifecycle."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      r.start_window_minutes >= 60 && r.completion_window_minutes > r.start_window_minutes
    ])
    error_message = "start_window_minutes must be at least 60, and completion_window_minutes must be strictly greater than it (AWS rejects an equal completion window)."
  }

  # AWS Backup's support for copying CONTINUOUS recovery points is limited by
  # resource type, and where it is unsupported the copy job fails nightly --
  # exactly the run-time failure class the rest of these validations exist to
  # move to plan time. Requiring an explicit opt-in keeps it a decision.
  validation {
    condition = alltrue([
      for r in var.rules :
      !r.enable_continuous_backup || length(r.copy_to) == 0 || r.acknowledge_continuous_backup_copy
    ])
    error_message = "A rule with enable_continuous_backup and copy_to must set acknowledge_continuous_backup_copy = true: cross-Region and cross-account copy of continuous recovery points is only supported for some resource types, and fails at job time for the rest."
  }

  # A copy_retention key that names no destination is almost always a typo that
  # would otherwise be silently ignored.
  validation {
    condition = alltrue(flatten([
      for r in var.rules : [
        for c in values(r.copy_retention) :
        !c.disable_cold_storage || c.cold_storage_after == null
      ]
    ]))
    error_message = "A copy_retention override cannot set both disable_cold_storage and cold_storage_after."
  }

  validation {
    condition = alltrue([
      for r in var.rules :
      length(setsubtract(keys(r.copy_retention), toset(r.copy_to))) == 0
    ])
    error_message = "Every copy_retention key must also appear in the same rule's copy_to list."
  }
}

###############################################################################
# COPY DESTINATIONS, cross-Region and cross-account targets
###############################################################################

variable "primary_vault" {
  description = <<-EOT
    The vault every backup job writes to first, in the plan's own account and Region.
    `region = null` places it in the provider's Region.
  EOT

  type = object({
    name                        = optional(string)
    region                      = optional(string)
    create_kms_key              = optional(bool, true)
    kms_key_arn                 = optional(string)
    kms_deletion_window_in_days = optional(number, 30)
    lock = optional(object({
      enabled             = optional(bool, true)
      mode                = optional(string, "governance")
      changeable_for_days = optional(number, 3)
      min_retention_days  = optional(number, 7)
      max_retention_days  = optional(number, 3650)
    }), {})
  })
  default = {}
}

variable "copy_destinations" {
  description = <<-EOT
    Copy targets, keyed by the logical name that `rules[*].copy_to` references.

    Two kinds:

      Managed:  `region` is set and `vault_arn` is null. The module creates the vault,
                  its KMS key and its Vault Lock in that Region of THIS account, using the
                  AWS provider's per-resource `region` argument. Any number of Regions works;
                  no provider aliases are needed.

      External, `vault_arn` is set. The module only references it. This is how a
                  cross-ACCOUNT destination is wired, because a different account needs
                  different credentials and therefore its own provider and, in practice,
                  its own state. Deploy `./modules/backup-vault` in the backup account with
                  `source_account_ids = [<this account>]` and pass its ARN here.

      lock_min_retention_days / lock_max_retention_days
                  For an external destination, the retention window its Vault Lock enforces.
                  Supplying these lets the module reject, at plan time, a retention that the
                  destination would reject nightly at run time. Omitting both is an ERROR
                  unless acknowledge_unchecked_copy_destinations is set: failing open with no
                  signal on the least observable hop is the wrong default for a guardrail.

      kms_key_arn_external
                  For an external destination, the ARN of the KMS key encrypting it.
                  REQUIRED when this module builds the backup role. The destination key
                  policy granting <this account>:root only DELEGATES to this account's IAM;
                  the role also needs an allow naming that key, or every encrypted
                  cross-account copy fails with AccessDenied.
  EOT

  type = map(object({
    region    = optional(string)
    vault_arn = optional(string)
    name      = optional(string)

    # No default, so "unset" stays distinguishable from "explicitly true" and the
    # validation below can reject it on an external destination instead of
    # silently ignoring it. Managed destinations get true.
    create_kms_key              = optional(bool)
    kms_key_arn                 = optional(string)
    kms_deletion_window_in_days = optional(number)
    lock = optional(object({
      enabled             = optional(bool, true)
      mode                = optional(string, "governance")
      changeable_for_days = optional(number, 3)
      min_retention_days  = optional(number, 7)
      max_retention_days  = optional(number, 3650)
    }), {})
    # For an EXTERNAL destination, the window its Vault Lock enforces. This module
    # cannot read a lock in another account, so declaring it is what allows the
    # plan-time retention check to cover the cross-account hop. Omitting BOTH is a
    # plan-time error unless acknowledge_unchecked_copy_destinations is set --
    # not a silent skip.
    lock_min_retention_days = optional(number)
    lock_max_retention_days = optional(number)

    # External destinations only: the ARN of the KMS key encrypting the
    # destination vault. Required for an encrypted cross-account copy, the
    # destination key policy delegating to `<source>:root` does not by itself
    # authorise anything; the source role also needs an IAM allow on that key.
    kms_key_arn_external = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, d in var.copy_destinations :
      (d.region != null) != (d.vault_arn != null)
    ])
    error_message = "Each copy destination must set exactly one of `region` (managed by this module) or `vault_arn` (external)."
  }

  validation {
    condition = alltrue([
      for k, d in var.copy_destinations :
      can(regex("^[a-z_][a-z0-9_]{0,49}$", k))
    ])
    error_message = "Copy destination keys must be lowercase snake_case identifiers."
  }

  validation {
    condition = alltrue([
      for k, d in var.copy_destinations :
      d.vault_arn == null || can(regex("^arn:aws[a-z-]*:backup:[a-z0-9-]+:[0-9]{12}:backup-vault:", d.vault_arn))
    ])
    error_message = "Each external destination's vault_arn must be a backup vault ARN (arn:aws:backup:<region>:<account>:backup-vault:<name>)."
  }

  # Fields that apply to only one kind of destination are rejected on the other
  # rather than silently ignored. A setting that appears to take effect and does
  # not is worse than one that is refused.
  validation {
    condition = alltrue([
      for k, d in var.copy_destinations :
      d.vault_arn != null || (d.kms_key_arn_external == null && d.lock_min_retention_days == null && d.lock_max_retention_days == null)
    ])
    error_message = "kms_key_arn_external, lock_min_retention_days and lock_max_retention_days apply only to external destinations (those with vault_arn set). A managed destination's key and lock are configured through create_kms_key/kms_key_arn and lock."
  }

  validation {
    condition = alltrue([
      for k, d in var.copy_destinations :
      d.region != null || (d.kms_key_arn == null && d.create_kms_key == null && d.kms_deletion_window_in_days == null)
    ])
    error_message = "create_kms_key and kms_key_arn apply only to managed destinations (those with region set). An external destination's key belongs to the account that owns it; declare it with kms_key_arn_external."
  }
}

variable "confirm_irreversible_compliance_lock" {
  description = <<-EOT
    Acknowledges that a COMPLIANCE-mode Vault Lock is permanent. Required before this module
    will create one on any vault it manages. See docs/adr/0001 for the rollout order.
  EOT
  type        = bool
  default     = false
}

###############################################################################
# RESOURCE SELECTION
###############################################################################

variable "selection_required_tags" {
  description = <<-EOT
    Tags a resource must carry, ALL of them, to be included in the plan.

    Rendered as `condition { string_equals { ... } }`, which AWS Backup evaluates with AND.
    Multiple `selection_tag` blocks would be evaluated with OR, so a resource tagged
    ToBackup=true with no Owner tag would still be backed up. That is the single most
    consequential correctness decision in this module; see docs/adr/0002.
  EOT
  type        = map(string)
  default = {
    ToBackup = "true"
  }

  validation {
    condition     = length(var.selection_required_tags) > 0
    error_message = "At least one required tag is needed; an unconditional selection would back up every resource in the account."
  }
}

variable "selection_required_tag_patterns" {
  description = <<-EOT
    Tags a resource must carry whose value matches a wildcard, evaluated with `string_like`
    and AND-ed with selection_required_tags.

    The default enforces that an Owner tag exists and looks like an address. That is
    deliberate rather than an empty default: the requirement is `ToBackup=true` AND
    `Owner=<owner@...>`, and a module whose defaults satisfy only half of it reproduces the
    exact gap it was built to prevent, just expressed as a missing condition rather than
    the wrong operator. Narrow it to your own domain, e.g. { Owner = "*@example.com" }.

    Set to {} only if ownership genuinely is not required.
  EOT
  type        = map(string)
  default = {
    Owner = "*@*"
  }
}

variable "selection_excluded_tag_patterns" {
  description = "Tags whose values must NOT match a wildcard, evaluated with `string_not_like` and AND-ed with the rest."
  type        = map(string)
  default     = {}
}

variable "selection_resources" {
  description = "Resource ARNs or ARN patterns in scope. [\"*\"] means every opted-in resource type."
  type        = list(string)
  default     = ["*"]
}

variable "selection_not_resources" {
  description = "Resource ARNs or ARN patterns excluded regardless of tags. Takes precedence over selection_resources."
  type        = list(string)
  default     = []
}

variable "opt_in_resource_types" {
  description = <<-EOT
    Per-Region AWS Backup resource-type opt-in. `resources = ["*"]` only covers types that are
    opted in for that Region, so an un-opted type is skipped silently and the plan appears to
    succeed while protecting less than it claims.

    Left null by default on purpose: `aws_backup_region_settings` is an account-and-Region
    SINGLETON. Two Terraform states that both manage it will fight, each apply reverting the
    other. Set it here only if this module is the single owner of that setting; otherwise
    manage it once in the account baseline and leave this null.
  EOT
  type        = map(bool)
  default     = null
}

variable "enable_cross_account_backup_global_setting" {
  description = <<-EOT
    Sets `isCrossAccountBackupEnabled = true` via aws_backup_global_settings. Cross-account
    copy fails without it. The API is only valid from the Organizations MANAGEMENT account,
    and the setting is another org-wide singleton, so it is off by default and belongs in the
    management account's own configuration.
  EOT
  type        = bool
  default     = false
}

###############################################################################
# Operational controls, notifications, restore testing, audit
###############################################################################

variable "enable_notifications" {
  description = "Create SNS topics, vault notifications and an EventBridge rule for failed jobs."
  type        = bool
  default     = true
}

variable "notification_subscriptions" {
  description = "protocol => endpoint subscribed to the primary-Region topic, e.g. { email = \"platform-oncall@example.com\" }."
  type        = map(string)
  default     = {}
}

variable "notification_events" {
  description = "Vault events published to SNS. Defaults to failures only; success events on a large estate are noise that trains people to ignore the topic."
  type        = list(string)
  default = [
    "BACKUP_JOB_FAILED",
    "BACKUP_JOB_EXPIRED",
    "COPY_JOB_FAILED",
    "RESTORE_JOB_FAILED",
    "S3_BACKUP_OBJECT_FAILED",
    "S3_RESTORE_OBJECT_FAILED",
  ]

  validation {
    condition     = length(var.notification_events) > 0
    error_message = "notification_events must not be empty when notifications are enabled."
  }
}

variable "enable_failure_alarm" {
  description = <<-EOT
    Create a CloudWatch alarm on failed backup jobs, fed by an EventBridge rule and a metric
    filter. An SNS notification is a message; an alarm is a state that can be dashboarded,
    escalated and reported on.
  EOT
  type        = bool
  default     = true
}

variable "enable_staleness_alarm" {
  description = <<-EOT
    Alarm when no backup job has SUCCEEDED within staleness_alarm_period_hours.

    This is the one alarm that catches the failure mode the others cannot: a plan that stopped
    running at all, a deleted selection, a revoked role, a resource type that was never opted
    in. It uses treat_missing_data = "breaching", because silence is exactly the symptom.
  EOT
  type        = bool
  default     = true
}

variable "staleness_alarm_period_hours" {
  description = "Hours without a successful backup job before the staleness alarm fires. Should exceed the longest gap between scheduled runs."
  type        = number
  default     = 26

  validation {
    condition     = var.staleness_alarm_period_hours >= 1 && var.staleness_alarm_period_hours <= 168
    error_message = "staleness_alarm_period_hours must be between 1 and 168 (CloudWatch alarm period limit)."
  }
}

variable "enable_restore_testing" {
  description = <<-EOT
    Create an AWS Backup restore testing plan.

    An untested backup is a hypothesis. Restore testing turns the assertion "we can recover"
    into a scheduled job that restores a real recovery point, records the outcome, and deletes
    the restored resource afterwards. This is the control most backup implementations lack.
  EOT
  type        = bool
  default     = true
}

variable "restore_testing" {
  description = <<-EOT
    Restore testing configuration.

      schedule                  When to run the test.
      start_window_hours        How long the test may wait for a start slot.
      selection_window_days     How far back to look for a recovery point to restore.
      recovery_point_types      SNAPSHOT and/or CONTINUOUS.
      resource_types            Resource types to test, each becoming a testing selection.
      validation_window_hours   How long the restored resource is kept for validation before
                                being cleaned up. Null uses the service default.
  EOT

  type = object({
    schedule                = optional(string, "cron(0 5 ? * SAT *)")
    schedule_timezone       = optional(string, "Etc/UTC")
    start_window_hours      = optional(number, 24)
    selection_window_days   = optional(number, 7)
    recovery_point_types    = optional(list(string), ["SNAPSHOT"])
    resource_types          = optional(list(string), ["EBS", "RDS", "DynamoDB"])
    validation_window_hours = optional(number, 4)
  })
  default = {}

  validation {
    condition     = var.restore_testing.selection_window_days >= 1 && var.restore_testing.selection_window_days <= 365
    error_message = "restore_testing.selection_window_days must be between 1 and 365."
  }

  validation {
    condition = alltrue([
      for t in var.restore_testing.recovery_point_types : contains(["SNAPSHOT", "CONTINUOUS"], t)
    ])
    error_message = "restore_testing.recovery_point_types entries must be SNAPSHOT or CONTINUOUS."
  }

  validation {
    condition     = length(var.restore_testing.resource_types) > 0
    error_message = "restore_testing.resource_types must name at least one resource type."
  }
}

variable "restore_testing_iam_role_arn" {
  description = <<-EOT
    Role AWS Backup assumes to perform restore tests. Restore is a genuinely privileged
    operation. It creates resources, so it is not folded into the backup role by default.
    Null reuses the module's backup role, which also carries the AWS restore policies.
  EOT
  type        = string
  default     = null
}

variable "enable_audit_framework" {
  description = <<-EOT
    Create an AWS Backup Audit Manager framework whose controls map onto this module's
    guarantees, so compliance is evaluated continuously rather than asserted in a README.
    Requires AWS Config to be recording in the account and Region.
  EOT
  type        = bool
  default     = true
}

variable "enable_audit_reports" {
  description = "Create daily Audit Manager report plans. Requires report_bucket_name."
  type        = bool
  default     = false
}

variable "report_bucket_name" {
  description = "Existing S3 bucket that receives audit report output. Required when enable_audit_reports is true."
  type        = string
  default     = null
}

variable "backup_role_arn" {
  description = "Existing AWS Backup service role to use. Null creates one with the AWS managed policies plus explicit KMS and copy permissions."
  type        = string
  default     = null
}

###############################################################################
# Vault access policy passthrough
#
# Exposed on the parent because a consumer of this module has no other way to
# reach the child, and a deny-delete policy with no exemption and no off switch
# is a lockout rather than a control.
###############################################################################

variable "enable_deny_delete_policy" {
  description = "Attach a vault access policy denying recovery point and vault deletion. Defence in depth behind Vault Lock, and the only deletion control in effect during the governance-mode validation window."
  type        = bool
  default     = true
}

variable "deny_delete_principals_except" {
  description = <<-EOT
    Principal ARNs exempt from the deny-delete vault policy, typically a break-glass role.
    Empty denies every principal.

    Exempt from the POLICY only. Nothing is exempt from Vault Lock, which is the point of it.
  EOT
  type        = list(string)
  default     = []
}

variable "vault_force_destroy" {
  description = "Allow `terraform destroy` to remove vaults that still hold recovery points. False everywhere that matters; a committed compliance lock refuses regardless."
  type        = bool
  default     = false
}

variable "acknowledge_unchecked_copy_destinations" {
  description = <<-EOT
    Permit copy destinations whose Vault Lock retention window was not declared.

    The plan-time retention check is this module's headline guarantee, and for an EXTERNAL
    destination it can only run if the caller supplies `lock_min_retention_days` /
    `lock_max_retention_days`, the module cannot read a Vault Lock in another account.

    Left false so that omitting them is an error rather than a silent skip. Failing open
    with no signal is the wrong default for a guardrail, and the cross-account hop is both
    the destination an operator has least visibility into and the one most likely to carry
    a stricter compliance lock.

    Set true to accept the gap knowingly; `unchecked_copy_destinations` names them either way.
  EOT
  type        = bool
  default     = false
}

variable "audit_scope_tag" {
  description = <<-EOT
    Single tag key/value the Audit Manager framework scopes its coverage control to.

    Null derives it from `selection_required_tags` when that holds exactly one entry, and
    omits the scope otherwise. AWS's ControlScope accepts at most one tag, so the module
    cannot simply pass the whole selection through, and the pattern-matched tags
    (`selection_required_tag_patterns`) are not expressible in a scope at all.

    The consequence is worth knowing: the framework's scope is necessarily WIDER than the
    plan's selection, so resources deliberately excluded for lacking an Owner tag will be
    reported as unprotected. Narrow this, or accept the finding as the signal that those
    resources need an owner.
  EOT
  type        = map(string)
  default     = null

  validation {
    condition     = var.audit_scope_tag == null || length(var.audit_scope_tag) == 1
    error_message = "audit_scope_tag must contain exactly one tag; the AWS ControlScope API accepts no more."
  }
}

variable "restore_time_target_minutes" {
  description = "RTO target, in MINUTES, asserted by the Audit Manager restore-time control. Default is 12 hours."
  type        = number
  default     = 720

  validation {
    condition     = var.restore_time_target_minutes >= 1
    error_message = "restore_time_target_minutes must be at least 1."
  }
}
