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
# The health check trap
# --------------------------------------------------------------------------

run "rejects_the_health_endpoint_for_load_balancing" {
  command = plan

  variables {
    health_check_path = "/-/health"
  }

  # GitLab documents this explicitly: /-/health fails whenever a backend
  # dependency is slow, so a transient database slowdown evicts every healthy
  # node and turns a degradation into an outage.
  expect_failures = [var.health_check_path]
}

run "rejects_the_legacy_health_check_path" {
  command = plan

  variables {
    health_check_path = "/health_check"
  }

  expect_failures = [var.health_check_path]
}

run "readiness_is_the_default" {
  command = apply

  assert {
    condition     = var.health_check_path == "/-/readiness"
    error_message = "The default health check path should be the one GitLab recommends for load balancing."
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
