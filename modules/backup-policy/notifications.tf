# Three layers, because they catch different failures: vault notifications (per
# vault, per Region), an EventBridge rule for copy jobs that fail before reaching
# the destination vault, and CloudWatch alarms to turn events into state.


###############################################################################
# Topic encryption
#
# `alias/aws/sns` cannot be used here. It is the AWS-MANAGED key: its policy
# grants only this account's IAM principals via kms:ViaService, and it cannot be
# edited. AWS Backup, EventBridge and CloudWatch therefore cannot obtain
# kms:GenerateDataKey* on it, so every publish fails with
# KMSAccessDeniedException, at delivery time, invisibly. Nothing shows up in
# the apply, in the alarm state or in the SNS console; you find out when a
# backup fails and nobody is paged.
#
# That failure would silence the staleness alarm in particular, which is the one
# control here that detects a plan that has stopped running at all.
#
# So: a customer managed key per Region, whose policy names the three service
# principals that publish to these topics.
###############################################################################

locals {
  sns_key_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountIAMPolicies"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowPublishingServicesToUseTheKey"
        Effect    = "Allow"
        Principal = { Service = local.sns_publishing_services }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
        Condition = {
          StringEqualsIfExists = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
    ]
  })
}

resource "aws_kms_key" "sns" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  description             = "Encrypts the ${var.name} backup notification topic in ${each.key}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = local.sns_key_policy
  tags                    = local.tags
}

resource "aws_kms_alias" "sns" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  name          = "alias/${var.name}-sns"
  target_key_id = aws_kms_key.sns[each.key].key_id
}

resource "aws_sns_topic" "backup" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  name              = "${var.name}-events"
  kms_master_key_id = aws_kms_key.sns[each.key].arn
  tags              = local.tags
}

###############################################################################
# Vault notifications
#
# Created here rather than inside the backup-vault module so they can carry a
# depends_on to the topic policy. PutBackupVaultNotifications validates that the
# topic policy permits backup.amazonaws.com to publish, so without this edge a
# cold apply can issue the call before the policy is attached, a
# non-deterministic first-apply failure that succeeds on re-run and therefore
# looks like flakiness rather than a missing dependency.
###############################################################################

resource "aws_backup_vault_notifications" "primary" {
  count = local.create_notifications ? 1 : 0

  region = local.primary_region

  backup_vault_name   = module.primary_vault.name
  sns_topic_arn       = aws_sns_topic.backup[local.primary_region].arn
  backup_vault_events = var.notification_events

  depends_on = [aws_sns_topic_policy.backup]
}

resource "aws_backup_vault_notifications" "copy" {
  for_each = local.create_notifications ? local.managed_destinations : {}

  region = coalesce(each.value.region, local.primary_region)

  backup_vault_name   = module.copy_vault[each.key].name
  sns_topic_arn       = aws_sns_topic.backup[coalesce(each.value.region, local.primary_region)].arn
  backup_vault_events = var.notification_events

  depends_on = [aws_sns_topic_policy.backup]
}

locals {
  sns_publishing_services = [
    "backup.amazonaws.com",
    "events.amazonaws.com",
    "cloudwatch.amazonaws.com",
  ]

  sns_topic_policy = {
    for r in local.managed_regions : r => jsonencode({
      Version = "2012-10-17"
      Statement = concat(
        [
          # Replacing the topic policy removes SNS's auto-generated
          # __default_statement_ID, which grants the topic owner SNS:*. Same-account
          # access still works through IAM, but console and subscription management
          # behave surprisingly without it, so it is restated rather than dropped.
          {
            Sid       = "AllowTopicOwner"
            Effect    = "Allow"
            Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
            Action = [
              "SNS:GetTopicAttributes",
              "SNS:SetTopicAttributes",
              "SNS:AddPermission",
              "SNS:RemovePermission",
              "SNS:DeleteTopic",
              "SNS:Subscribe",
              "SNS:ListSubscriptionsByTopic",
              "SNS:Publish",
            ]
            Resource = "arn:${local.partition}:sns:${r}:${local.account_id}:${var.name}-events"
          },
        ],
        [
          for svc in local.sns_publishing_services : {
            Sid       = "Allow${replace(title(split(".", svc)[0]), "-", "")}Publish"
            Effect    = "Allow"
            Principal = { Service = svc }
            Action    = "SNS:Publish"
            Resource  = "arn:${local.partition}:sns:${r}:${local.account_id}:${var.name}-events"
            # IfExists, matching the KMS key policy that gates the same publish.
            # A plain StringEquals on a context key a service does not populate
            # evaluates FALSE and drops the message, the same silent
            # delivery failure this file's header comment is about. The two
            # policies must agree, or the careful one is wasted.
            Condition = {
              StringEqualsIfExists = { "aws:SourceAccount" = local.account_id }
            }
          }
        ],
        [
          # Restated from the pre-jsonencode version of this policy.
          {
            Sid       = "DenyInsecureTransport"
            Effect    = "Deny"
            Principal = { AWS = "*" }
            Action    = "SNS:Publish"
            Resource  = "arn:${local.partition}:sns:${r}:${local.account_id}:${var.name}-events"
            Condition = {
              Bool = { "aws:SecureTransport" = "false" }
            }
          },
        ],
      )
    })
  }
}

resource "aws_sns_topic_policy" "backup" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  arn    = aws_sns_topic.backup[each.key].arn
  policy = local.sns_topic_policy[each.key]
}

resource "aws_sns_topic_subscription" "backup" {
  for_each = local.create_notifications ? var.notification_subscriptions : {}

  region = local.primary_region

  topic_arn = aws_sns_topic.backup[local.primary_region].arn
  protocol  = each.key
  endpoint  = each.value
}

###############################################################################
# EventBridge -> SNS for every terminal failure state.
###############################################################################

resource "aws_cloudwatch_event_rule" "job_failed" {
  count = local.create_notifications ? 1 : 0

  region = local.primary_region

  name        = "${var.name}-job-failed"
  description = "AWS Backup backup, copy or restore job reached a terminal failure state"
  tags        = local.tags

  event_pattern = jsonencode({
    source        = ["aws.backup"]
    "detail-type" = ["Backup Job State Change", "Copy Job State Change", "Restore Job State Change"]
    detail = {
      state = ["FAILED", "ABORTED", "EXPIRED", "PARTIAL"]
    }
  })
}

resource "aws_cloudwatch_event_target" "job_failed" {
  count = local.create_notifications ? 1 : 0

  region = local.primary_region

  rule      = aws_cloudwatch_event_rule.job_failed[0].name
  target_id = "sns"
  arn       = aws_sns_topic.backup[local.primary_region].arn

  depends_on = [aws_sns_topic_policy.backup]
}

###############################################################################
# Alarms
#
# AWS Backup publishes NumberOfBackupJobsFailed and NumberOfBackupJobsCompleted
# to the AWS/Backup namespace.
###############################################################################

resource "aws_cloudwatch_metric_alarm" "job_failed" {
  count = local.create_notifications && var.enable_failure_alarm ? 1 : 0

  region = local.primary_region

  alarm_name        = "${var.name}-backup-jobs-failed"
  alarm_description = "One or more AWS Backup jobs failed in the last hour writing to ${module.primary_vault.name}."

  namespace   = "AWS/Backup"
  metric_name = "NumberOfBackupJobsFailed"
  statistic   = "Sum"

  # Scoped to this module's own vault. Undimensioned, the metric covers every
  # backup job in the account and Region, so in an estate with more than one
  # plan the alarm would fire on somebody else's failure and stay silent on
  # nothing at all.
  dimensions = {
    BackupVaultName = module.primary_vault.name
  }
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"

  # A failure metric that is simply absent means no jobs failed, which is the
  # good case. Staleness is caught by the separate alarm below.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.backup[local.primary_region].arn]
  ok_actions    = [aws_sns_topic.backup[local.primary_region].arn]

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "stale" {
  count = local.create_notifications && var.enable_staleness_alarm ? 1 : 0

  region = local.primary_region

  alarm_name        = "${var.name}-no-successful-backup"
  alarm_description = "No AWS Backup job has completed successfully into ${module.primary_vault.name} in ${var.staleness_alarm_period_hours}h. A plan that stops running produces no failure events, so this is the only alarm that sees it."

  namespace   = "AWS/Backup"
  metric_name = "NumberOfBackupJobsCompleted"
  statistic   = "Sum"

  dimensions = {
    BackupVaultName = module.primary_vault.name
  }
  # Period x EvaluationPeriods is the alarm's total evaluation window and CloudWatch
  # caps that product at 86400 seconds, which is why the variable stops at 24 hours.
  # A longer lookback is not expressible as a metric alarm in any arrangement.
  period              = var.staleness_alarm_period_hours * 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"

  # The whole point: absence of data IS the failure. Getting this backwards is
  # the classic monitoring bug: the alarm stays green precisely when the system
  # has stopped working.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.backup[local.primary_region].arn]
  ok_actions    = [aws_sns_topic.backup[local.primary_region].arn]

  tags = local.tags
}
