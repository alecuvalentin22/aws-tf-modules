###############################################################################
# Notifications and alarms
#
# Three layers, because they detect different failures:
#
#   Vault notifications  per-vault, per-Region. Catches a job that failed at the
#                        vault. Cannot cross a Region, hence one topic per Region.
#   EventBridge rule     catches copy jobs that fail before ever reaching the
#                        destination vault, which vault notifications never see.
#   CloudWatch alarms    turn events into state. A failure alarm can be
#                        dashboarded and escalated; a staleness alarm catches the
#                        failure mode that produces no event at all.
###############################################################################

resource "aws_sns_topic" "backup" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  name              = "${var.name}-events"
  kms_master_key_id = "alias/aws/sns"
  tags              = local.tags
}

data "aws_iam_policy_document" "sns" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  statement {
    sid       = "AllowAWSBackupPublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.backup[each.key].arn]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.backup[each.key].arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AllowCloudWatchAlarmsPublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.backup[each.key].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.backup[each.key].arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "backup" {
  for_each = local.create_notifications ? toset(local.managed_regions) : toset([])

  region = each.key

  arn    = aws_sns_topic.backup[each.key].arn
  policy = data.aws_iam_policy_document.sns[each.key].json
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

  alarm_name          = "${var.name}-backup-jobs-failed"
  alarm_description   = "One or more AWS Backup jobs failed in the last hour for plan ${var.name}."
  namespace           = "AWS/Backup"
  metric_name         = "NumberOfBackupJobsFailed"
  statistic           = "Sum"
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
  alarm_description = "No AWS Backup job has completed successfully in ${var.staleness_alarm_period_hours}h for plan ${var.name}. A plan that stops running produces no failure events, so this is the only alarm that sees it."

  namespace           = "AWS/Backup"
  metric_name         = "NumberOfBackupJobsCompleted"
  statistic           = "Sum"
  period              = var.staleness_alarm_period_hours * 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"

  # The whole point: absence of data IS the failure. Getting this backwards is
  # the classic monitoring bug -- the alarm stays green precisely when the system
  # has stopped working.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.backup[local.primary_region].arn]
  ok_actions    = [aws_sns_topic.backup[local.primary_region].arn]

  tags = local.tags
}
