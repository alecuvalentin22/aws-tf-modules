mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name        = "gitlab"
  instance_id = "i-0123456789abcdef0"
  base_url    = "https://gitlab.example.com"
}

# --------------------------------------------------------------------------
# Silence is a failure mode
#
# The classic single-node monitoring bug: a dead host stops publishing, and an
# alarm that treats missing data as "not breaching" goes GREEN at exactly the
# moment the platform dies.
# --------------------------------------------------------------------------

run "every_critical_alarm_treats_missing_data_as_breaching" {
  command = apply

  variables {
    cloudwatch_agent_installed = true
    enable_sidekiq_alarms      = true
    backup_bucket_name         = "gitlab-backups"

    canaries = {
      clone_https = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "clone-https.zip"
      }
    }
    canary_execution_role_arn = "arn:aws:iam::111111111111:role/canary"
    canary_results_bucket     = "canary-results"
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.instance_status.treat_missing_data == "breaching"
    error_message = "A terminated instance stops publishing metrics; treating that as not-breaching turns the alarm green when the platform dies."
  }

  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.repository_disk : a.treat_missing_data == "breaching"
    ])
    error_message = "No disk metric means the agent stopped, the instance died, or the volume was unmounted. All three are worse than a full disk."
  }

  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.canary_failed : a.treat_missing_data == "breaching"
    ])
    error_message = "A canary that stops reporting has itself failed, or the thing it watches took it down."
  }

  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.sidekiq_queue_latency : a.treat_missing_data == "breaching"
    ])
    error_message = "Sidekiq not reporting at all is worse than a slow queue."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.backup_freshness[0].treat_missing_data == "breaching"
    error_message = "A stalled backup job emits nothing at all, so absence of data is the symptom."
  }
}

# --------------------------------------------------------------------------
# An alarm that cannot match a metric is the same defect as an alarm on a metric
# nobody publishes. Because every alarm here treats missing data as breaching,
# both page continuously rather than sitting quietly in INSUFFICIENT_DATA.
# --------------------------------------------------------------------------

run "every_alarm_carries_a_dimension_set" {
  command = apply

  variables {
    cloudwatch_agent_installed = true
    enable_sidekiq_alarms      = true
    backup_bucket_name         = "gitlab-backups"
  }

  # CloudWatch matches on the exact dimension set, so an empty one watches the
  # zero-dimension metric, which is not the one anything publishes.
  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.sidekiq_queue_latency :
      a.dimensions["InstanceId"] == var.instance_id
    ])
    error_message = "A dimensionless Sidekiq alarm matches no published metric, and with missing data treated as breaching it pages continuously while the platform is healthy."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.instance_status.dimensions["InstanceId"] == var.instance_id
    error_message = "The host alarm must be dimensioned to the instance it claims to watch."
  }

  # The agent publishes disk metrics under path as well as InstanceId, and an alarm
  # matches on the exact set or on nothing at all.
  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.repository_disk :
      a.dimensions["path"] == var.repository_volume_path && a.dimensions["InstanceId"] == var.instance_id
    ])
    error_message = "The disk alarms must carry the dimension set the CloudWatch agent is configured to publish."
  }
}

run "gitlab_metric_dimensions_can_be_overridden" {
  command = apply

  variables {
    enable_sidekiq_alarms = true

    gitlab_metric_dimensions = {
      Host  = "gitlab-01"
      Queue = "default"
    }
  }

  # Whatever ships the Prometheus metrics decides the dimension set; the module
  # cannot guess it.
  assert {
    condition = alltrue([
      for a in aws_cloudwatch_metric_alarm.sidekiq_queue_latency :
      a.dimensions["Queue"] == "default" && !contains(keys(a.dimensions), "InstanceId")
    ])
    error_message = "An explicit dimension set should replace the default, not extend it."
  }
}

# --------------------------------------------------------------------------
# Backup freshness
# --------------------------------------------------------------------------

run "the_backup_alarm_counts_writes_under_the_backup_prefix" {
  command = apply

  variables {
    backup_bucket_name   = "gitlab-backups"
    backup_object_prefix = "daily/"
    backup_max_age_hours = 24
  }

  # NumberOfObjects is a once-a-day storage metric counting the whole bucket. It
  # reports the same healthy number forever once one backup exists, so an alarm
  # on it detects an empty bucket and nothing else.
  assert {
    condition     = aws_cloudwatch_metric_alarm.backup_freshness[0].metric_name == "PutRequests"
    error_message = "Backup staleness needs a request metric, not a daily storage metric."
  }

  assert {
    condition     = aws_s3_bucket_metric.backups[0].filter[0].prefix == "daily/"
    error_message = "The request-metrics filter must be scoped to the backup prefix; an unrelated write elsewhere in the bucket is not a backup."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.backup_freshness[0].dimensions["FilterId"] == aws_s3_bucket_metric.backups[0].name
    error_message = "The alarm must reference the filter, or it measures every write to the bucket."
  }
}

run "rejects_a_backup_window_longer_than_a_cloudwatch_period" {
  command = plan

  variables {
    backup_bucket_name   = "gitlab-backups"
    backup_max_age_hours = 26
  }

  # 26 hours is 93600 seconds. CloudWatch caps an alarm period at 86400 and
  # rejects the alarm at apply time, so the guardrail belongs at plan time.
  expect_failures = [var.backup_max_age_hours]
}

# --------------------------------------------------------------------------
# The health check trap
# --------------------------------------------------------------------------

run "rejects_the_health_endpoint_for_load_balancing" {
  command = plan

  variables {
    health_check_path = "/-/health"
  }

  # /-/health is the SHALLOW endpoint: it reports that the application server is
  # running and nothing more, so a node whose database has gone away still passes
  # and keeps receiving traffic.
  expect_failures = [var.health_check_path]
}

run "rejects_the_legacy_health_check_path" {
  command = plan

  variables {
    health_check_path = "/health_check"
  }

  expect_failures = [var.health_check_path]
}

run "rejects_the_deep_readiness_check_for_load_balancing" {
  command = plan

  variables {
    health_check_path = "/-/readiness?all=1"
  }

  # The opposite mistake, and the one people make after learning the first: ?all=1
  # checks shared backend dependencies, so a single slow database makes every node
  # report unready at once and the pool drains completely.
  expect_failures = [var.health_check_path]
}

run "readiness_is_the_default_and_reaches_the_caller" {
  command = apply

  # The module builds no target group, so the useful assertion is that the
  # validated value is what the caller receives, not that a default equals itself.
  assert {
    condition     = output.health_check_path == "/-/readiness"
    error_message = "The health check path should be exported for the caller's target group."
  }
}

# --------------------------------------------------------------------------
# Alarms that cannot fire are worse than no alarms
# --------------------------------------------------------------------------

run "no_disk_or_memory_alarms_without_the_cloudwatch_agent" {
  command = apply

  # EC2 publishes neither memory nor disk usage. Creating these without the
  # agent yields alarms stuck in INSUFFICIENT_DATA forever, which on a dashboard
  # is indistinguishable from healthy.
  assert {
    condition     = length(aws_cloudwatch_metric_alarm.repository_disk) == 0
    error_message = "Without the agent these alarms reference metrics that will never exist."
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.memory) == 0
    error_message = "Without the agent the memory alarm can never fire."
  }

  # And the omission is stated rather than left for someone to notice.
  assert {
    condition = anytrue([
      for gap in output.coverage_gaps : strcontains(gap, "CloudWatch agent")
    ])
    error_message = "An unmonitored dimension must be reported, not passed over."
  }
}

run "the_agent_alarms_appear_once_the_agent_is_declared" {
  command = apply

  variables {
    cloudwatch_agent_installed = true
  }

  assert {
    condition     = length(aws_cloudwatch_metric_alarm.repository_disk) == 3
    error_message = "Disk should alarm at three levels: the useful property is lead time, not detection."
  }

  assert {
    condition = alltrue([
      for gap in output.coverage_gaps : !strcontains(gap, "CloudWatch agent")
    ])
    error_message = "The gap should disappear once the dimension is covered."
  }
}

# --------------------------------------------------------------------------
# Coverage reporting
# --------------------------------------------------------------------------

run "an_unconfigured_module_reports_everything_it_is_not_watching" {
  command = apply

  # The dangerous state for a monitoring stack is looking complete while missing
  # the signal that would have given warning.
  assert {
    condition     = length(output.coverage_gaps) == 4
    error_message = "With nothing enabled, all four coverage gaps should be reported."
  }

  assert {
    condition = anytrue([
      for gap in output.coverage_gaps : strcontains(gap, "clone")
    ])
    error_message = "Without a canary nothing proves a developer can actually clone; host metrics only show the box is alive."
  }
}

run "a_fully_configured_module_reports_no_gaps" {
  command = apply

  variables {
    cloudwatch_agent_installed = true
    enable_sidekiq_alarms      = true
    backup_bucket_name         = "gitlab-backups"

    canaries = {
      clone_https = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "clone-https.zip"
      }
      clone_ssh = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "clone-ssh.zip"
      }
    }
    canary_execution_role_arn = "arn:aws:iam::111111111111:role/canary"
    canary_results_bucket     = "canary-results"
  }

  assert {
    condition     = length(output.coverage_gaps) == 0
    error_message = "With every dimension covered the gap list should be empty."
  }

  # HTTPS and SSH are separate failure domains: an SSH-only outage is invisible
  # to every HTTPS check.
  assert {
    condition     = length(aws_synthetics_canary.this) == 2
    error_message = "Both Git transports should be exercised."
  }
}

# --------------------------------------------------------------------------
# Input sanity
# --------------------------------------------------------------------------

run "rejects_disk_thresholds_that_do_not_increase" {
  command = plan

  variables {
    disk_thresholds = {
      ticket = 90
      warn   = 80
      page   = 70
    }
  }

  expect_failures = [var.disk_thresholds]
}

run "rejects_a_page_threshold_with_no_headroom" {
  command = plan

  variables {
    disk_thresholds = {
      ticket = 70
      warn   = 80
      page   = 100
    }
  }

  expect_failures = [var.disk_thresholds]
}

run "rejects_a_non_https_base_url" {
  command = plan

  variables {
    base_url = "http://gitlab.example.com"
  }

  expect_failures = [var.base_url]
}

run "rejects_a_canary_name_synthetics_would_truncate" {
  command = plan

  variables {
    name = "gitlab-production"

    canaries = {
      clone_over_https = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "clone-https.zip"
      }
    }
    canary_execution_role_arn = "arn:aws:iam::111111111111:role/canary"
    canary_results_bucket     = "canary-results"
  }

  # Synthetics caps names at 21 characters. Truncating to fit collapses two keys
  # sharing a prefix onto one name, and the alarm then watches a canary other
  # than the one it is named after.
  expect_failures = [aws_synthetics_canary.this["clone_over_https"]]
}

run "canaries_require_their_execution_role" {
  command = plan

  variables {
    canaries = {
      clone_https = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "clone-https.zip"
      }
    }
    canary_results_bucket = "canary-results"
    # canary_execution_role_arn deliberately omitted.
  }

  expect_failures = [aws_synthetics_canary.this["clone_https"]]
}

run "rejects_subscriptions_that_would_be_silently_dropped" {
  command = plan

  variables {
    alarm_topic_arn     = "arn:aws:sns:eu-central-1:111111111111:existing"
    alarm_subscriptions = { email = "platform-oncall@example.com" }
  }

  # Attaching these to a topic the module does not own is not possible, and
  # dropping them quietly would leave a caller believing the alarms reach someone.
  expect_failures = [var.alarm_subscriptions]
}

run "the_canary_alarm_period_follows_the_canary_schedule" {
  command = apply

  variables {
    canaries = {
      clone_https = {
        artifact_s3_bucket  = "canary-artifacts"
        artifact_s3_key     = "clone-https.zip"
        schedule_expression = "rate(15 minutes)"
      }
      web_login = {
        artifact_s3_bucket = "canary-artifacts"
        artifact_s3_key    = "web-login.zip"
      }
    }
    canary_execution_role_arn = "arn:aws:iam::111111111111:role/canary"
    canary_results_bucket     = "canary-results"
  }

  # A fixed five-minute period leaves two of every three periods empty for a
  # 15-minute canary, and with missing data treated as breaching that alarm is in
  # ALARM permanently while the canary is passing.
  assert {
    condition     = aws_cloudwatch_metric_alarm.canary_failed["clone_https"].period == 900
    error_message = "The alarm period must be at least the canary's own interval."
  }

  assert {
    condition     = aws_cloudwatch_metric_alarm.canary_failed["web_login"].period == 300
    error_message = "A canary on the default rate(5 minutes) should keep a 300-second period."
  }
}
