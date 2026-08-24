# Alarms whose absence of data means failure use treat_missing_data = "breaching".
# A dead host stops publishing, so the opposite setting turns the alarm green at
# the moment the platform dies.


terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}

locals {
  tags = merge(
    {
      ManagedBy = "terraform"
      Module    = "gitlab-observability"
    },
    var.tags,
  )

  create_topic = var.alarm_topic_arn == null
  topic_arn    = local.create_topic ? aws_sns_topic.alarms[0].arn : var.alarm_topic_arn

  alarm_actions = [local.topic_arn]

  # Alarms that depend on the CloudWatch agent. EC2 publishes neither memory nor
  # disk usage on its own, so without the agent these reference metrics that will
  # never exist and sit in INSUFFICIENT_DATA forever, which reads as healthy.
  agent_alarms_enabled = var.cloudwatch_agent_installed

  disk_levels = {
    ticket = { threshold = var.disk_thresholds.ticket, severity = "ticket" }
    warn   = { threshold = var.disk_thresholds.warn, severity = "warning" }
    page   = { threshold = var.disk_thresholds.page, severity = "page" }
  }
}

resource "aws_sns_topic" "alarms" {
  count = local.create_topic ? 1 : 0

  name = "${var.name}-alarms"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "alarms" {
  for_each = local.create_topic ? var.alarm_subscriptions : {}

  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = each.key
  endpoint  = each.value
}

# Canaries. A git clone over HTTPS and over SSH is the only check that exercises
# Gitaly, storage, auth and the network in one go. The two transports are separate
# failure domains, so an SSH outage is invisible to every HTTPS check.

resource "aws_synthetics_canary" "this" {
  for_each = var.canaries

  name                 = substr(replace("${var.name}-${each.key}", "_", "-"), 0, 21)
  artifact_s3_location = "s3://${var.canary_results_bucket}/${var.name}/${each.key}"
  execution_role_arn   = var.canary_execution_role_arn
  handler              = each.value.handler
  runtime_version      = each.value.runtime_version
  s3_bucket            = each.value.artifact_s3_bucket
  s3_key               = each.value.artifact_s3_key
  start_canary         = true
  tags                 = local.tags

  schedule {
    expression = each.value.schedule_expression
  }

  run_config {
    timeout_in_seconds = each.value.timeout_seconds
    active_tracing     = each.value.active_tracing

    environment_variables = {
      GITLAB_BASE_URL = var.base_url
    }
  }

  lifecycle {
    precondition {
      condition     = var.canary_execution_role_arn != null
      error_message = "canary_execution_role_arn is required when canaries are defined."
    }

    precondition {
      condition     = var.canary_results_bucket != null
      error_message = "canary_results_bucket is required when canaries are defined."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "canary_failed" {
  for_each = var.canaries

  alarm_name        = "${var.name}-canary-${each.key}"
  alarm_description = "Synthetic canary ${each.key} is failing against ${var.base_url}. This is a user-visible failure, not a proxy for one."

  namespace   = "CloudWatchSynthetics"
  metric_name = "SuccessPercent"
  statistic   = "Average"
  dimensions = {
    CanaryName = aws_synthetics_canary.this[each.key].name
  }

  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 100
  comparison_operator = "LessThanThreshold"

  # A canary that stops reporting has itself failed, or the thing it watches has
  # taken it down. Either way, silence is the alarm condition.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = local.tags
}

# Sidekiq queue latency usually climbs 10 to 30 minutes before users notice, so
# this is the one alarm here that fires ahead of impact rather than after it.

resource "aws_cloudwatch_metric_alarm" "sidekiq_queue_latency" {
  for_each = var.enable_sidekiq_alarms ? {
    warn = { threshold = var.sidekiq_queue_latency_thresholds.warn, severity = "warning" }
    page = { threshold = var.sidekiq_queue_latency_thresholds.page, severity = "page" }
  } : {}

  alarm_name        = "${var.name}-sidekiq-queue-latency-${each.key}"
  alarm_description = "Sidekiq queue latency above ${each.value.threshold}s. This usually leads user-visible degradation by 10-30 minutes, so it is worth acting on before anyone reports a problem."

  namespace   = var.gitlab_metrics_namespace
  metric_name = "sidekiq_queue_latency_seconds"
  statistic   = "Maximum"

  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"

  # Sidekiq not reporting at all means the exporter or Sidekiq itself is down,
  # which is worse than a slow queue.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = merge(local.tags, { Severity = each.value.severity })
}

resource "aws_cloudwatch_metric_alarm" "repository_disk" {
  for_each = local.agent_alarms_enabled ? local.disk_levels : {}

  alarm_name        = "${var.name}-repo-disk-${each.key}"
  alarm_description = "Repository volume ${var.repository_volume_path} above ${each.value.threshold}% used. Disk-full is the most common cause of a self-managed GitLab outage and is entirely preventable with warning."

  namespace   = var.cloudwatch_agent_namespace
  metric_name = "disk_used_percent"
  statistic   = "Maximum"
  dimensions = {
    InstanceId = var.instance_id
    path       = var.repository_volume_path
  }

  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanThreshold"

  # No disk metric means the agent stopped, the instance died, or the volume was
  # unmounted. All three are worse than a full disk.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = merge(local.tags, { Severity = each.value.severity })
}

resource "aws_cloudwatch_metric_alarm" "memory" {
  count = local.agent_alarms_enabled ? 1 : 0

  alarm_name        = "${var.name}-memory"
  alarm_description = "Memory utilisation above 90%. Sustained pressure here precedes a Gitaly OOM, which on a single node takes the whole platform with it."

  namespace   = var.cloudwatch_agent_namespace
  metric_name = "mem_used_percent"
  statistic   = "Average"
  dimensions = {
    InstanceId = var.instance_id
  }

  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 90
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = local.tags
}

resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name        = "${var.name}-instance-status"
  alarm_description = "EC2 status checks failing for the GitLab instance."

  namespace   = "AWS/EC2"
  metric_name = "StatusCheckFailed"
  statistic   = "Maximum"
  dimensions = {
    InstanceId = var.instance_id
  }

  period              = 60
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"

  # A terminated or unreachable instance stops publishing. Treating that as
  # "not breaching" is the classic single-node monitoring bug: the alarm goes
  # green at exactly the moment the platform dies.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = local.tags
}

resource "aws_cloudwatch_metric_alarm" "backup_freshness" {
  count = var.backup_bucket_name == null ? 0 : 1

  alarm_name        = "${var.name}-backup-stale"
  alarm_description = "No GitLab backup written to s3://${var.backup_bucket_name} in ${var.backup_max_age_hours}h. A backup job that stops producing raises nothing on its own."

  namespace   = "AWS/S3"
  metric_name = "NumberOfObjects"
  statistic   = "Average"
  dimensions = {
    BucketName  = var.backup_bucket_name
    StorageType = "AllStorageTypes"
  }

  period              = var.backup_max_age_hours * 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = local.tags
}
