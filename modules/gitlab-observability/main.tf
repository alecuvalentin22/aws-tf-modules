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
  # never exist.
  #
  # Worth being precise about what that costs, because the usual phrasing is
  # wrong for this module. An alarm on a metric nobody publishes sits in
  # INSUFFICIENT_DATA only while missing data is treated as missing. Every alarm
  # here treats it as breaching, on purpose, so the same alarm goes to ALARM on
  # the first evaluation and pages forever. That is worse than a silent gap: it
  # is a page nobody can act on, which is how a team learns to ignore the alarm
  # that later matters.
  agent_alarms_enabled = var.cloudwatch_agent_installed

  disk_levels = {
    ticket = { threshold = var.disk_thresholds.ticket, severity = "ticket" }
    warn   = { threshold = var.disk_thresholds.warn, severity = "warning" }
    page   = { threshold = var.disk_thresholds.page, severity = "page" }
  }

  # A CloudWatch alarm matches a metric only on an exact dimension set. An alarm
  # with no dimensions therefore watches the zero-dimension metric, which is not
  # the one anything publishes: combined with treat_missing_data = "breaching" it
  # pages continuously while nothing is wrong. That is the same defect this module
  # refuses to commit for disk and memory, so the GitLab-sourced alarms get a
  # dimension set too.
  gitlab_dimensions = length(var.gitlab_metric_dimensions) > 0 ? var.gitlab_metric_dimensions : {
    InstanceId = var.instance_id
  }

  # The CloudWatch agent publishes disk_used_percent with the full dimension set it
  # collected under: path, device and fstype, plus whatever append_dimensions adds
  # (InstanceId, ImageId, InstanceType by default). CloudWatch matches an alarm on
  # the EXACT set, so {InstanceId, path} matches nothing a default agent config
  # emits, and because these alarms treat missing data as breaching the result is
  # not a quiet alarm: it is three disk alarms in ALARM from the first minute,
  # paging forever, which trains everyone to ignore them.
  #
  # The agent has to be told to publish this set, with
  # aggregation_dimensions = [["InstanceId","path"]] for disk and [["InstanceId"]]
  # for memory. These variables exist so the alarms can be matched to an agent
  # configured differently rather than silently missing it.
  disk_dimensions = length(var.disk_metric_dimensions) > 0 ? var.disk_metric_dimensions : {
    InstanceId = var.instance_id
    path       = var.repository_volume_path
  }

  memory_dimensions = length(var.memory_metric_dimensions) > 0 ? var.memory_metric_dimensions : {
    InstanceId = var.instance_id
  }

  # A canary alarm's period has to be at least the canary's own interval, or most
  # periods contain no run at all. Parsed from rate(N unit); a cron() schedule is
  # not decomposable here, so those fall back to the declared default and the
  # caller can override it.
  canary_rate_seconds = {
    for k, c in var.canaries : k => (
      can(regex("^rate\\((\\d+) (minute|minutes|hour|hours)\\)$", c.schedule_expression))
      ? tonumber(regex("^rate\\((\\d+) ", c.schedule_expression)[0]) *
      (strcontains(c.schedule_expression, "hour") ? 3600 : 60)
      : null
    )
  }

  canary_periods = {
    for k, c in var.canaries : k => coalesce(
      c.alarm_period_seconds,
      local.canary_rate_seconds[k],
      300,
    )
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

  name                 = replace("${var.name}-${each.key}", "_", "-")
  artifact_s3_location = "s3://${var.canary_results_bucket}/${var.name}/${each.key}"
  execution_role_arn   = var.canary_execution_role_arn
  handler              = each.value.handler
  runtime_version      = each.value.runtime_version
  s3_bucket            = each.value.artifact_s3_bucket
  s3_key               = each.value.artifact_s3_key
  start_canary         = true
  tags                 = local.tags

  # Synthetics leaves the underlying Lambda behind on destroy otherwise, and the
  # orphan keeps its log group and its ENIs.
  delete_lambda = true

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

    # Synthetics caps canary names at 21 characters. Truncating to fit is worse
    # than refusing: two keys sharing a prefix collapse to the same name, and the
    # alarm then watches a canary other than the one it is named after.
    precondition {
      condition     = length("${var.name}-${each.key}") <= 21
      error_message = "Canary name \"${var.name}-${each.key}\" is longer than the 21 characters Synthetics allows. Shorten var.name or the canary key."
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

  # Derived from the canary's own schedule, not fixed at five minutes. A canary on
  # rate(15 minutes) leaves two of every three 5-minute periods empty, and with
  # missing data treated as breaching that alarm is in ALARM permanently while the
  # canary is passing.
  period              = local.canary_periods[each.key]
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
  dimensions  = local.gitlab_dimensions

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
  dimensions  = local.disk_dimensions

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
  dimensions  = local.memory_dimensions

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

# Backup freshness.
#
# The obvious implementation is an alarm on AWS/S3 NumberOfObjects, and it does
# not work. That is a storage metric: it is published once a day, it counts every
# object in the bucket, and it therefore reports the same healthy number forever
# once a single backup exists. An alarm on it detects an empty bucket, which is
# not the failure anyone is worried about.
#
# S3 request metrics are the ones with a one-minute resolution, and they can be
# scoped to a prefix. PutRequests summed over the backup window answers the
# question actually being asked: has anything been written under the backup
# prefix recently. It costs a per-request metrics charge on that prefix.
resource "aws_s3_bucket_metric" "backups" {
  count = var.backup_bucket_name == null ? 0 : 1

  bucket = var.backup_bucket_name
  name   = "${var.name}-backups"

  filter {
    prefix = var.backup_object_prefix
  }
}

resource "aws_cloudwatch_metric_alarm" "backup_freshness" {
  count = var.backup_bucket_name == null ? 0 : 1

  alarm_name        = "${var.name}-backup-stale"
  alarm_description = "No object written under s3://${var.backup_bucket_name}/${var.backup_object_prefix} in ${var.backup_max_age_hours}h. A backup job that stops producing raises nothing on its own, and a run that exits zero while writing nothing raises less than that."

  namespace   = "AWS/S3"
  metric_name = "PutRequests"
  statistic   = "Sum"
  dimensions = {
    BucketName = var.backup_bucket_name
    FilterId   = aws_s3_bucket_metric.backups[0].name
  }

  period              = var.backup_max_age_hours * 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"

  # No writes and no datapoints are the same event here, so the two must be
  # treated the same way.
  treat_missing_data = "breaching"

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
  tags          = local.tags
}
