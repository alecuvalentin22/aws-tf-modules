variable "name" {
  description = "Base name for the resources this module creates."
  type        = string
  default     = "gitlab"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,29}$", var.name))
    error_message = "name must be 2-30 characters of lowercase letters, digits and hyphens."
  }
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}

variable "instance_id" {
  description = "EC2 instance running GitLab, used to dimension the host alarms."
  type        = string
}

variable "base_url" {
  description = "Base URL the canaries call, for example https://gitlab.example.com."
  type        = string

  validation {
    condition     = can(regex("^https://", var.base_url))
    error_message = "base_url must be an https:// URL."
  }
}

###############################################################################
# Load balancer health check
###############################################################################

variable "health_check_path" {
  description = <<-EOT
    Path the load balancer health check calls. Consumed by the caller's target group;
    this module creates no load balancer, so the value is validated and re-exported
    rather than attached to anything here.

    The four endpoints differ, and picking the wrong one fails in opposite directions:

      /-/liveness         Is the Rails process up. Says nothing about whether it can
                          serve a request, so a node with a dead database stays in
                          the pool.
      /-/health           Shallow: the application server is running. Same problem as
                          liveness for a load balancer decision, and it is the one
                          most often chosen because of the name.
      /-/readiness        Deep enough to be useful and scoped to this node. The
                          default, and what GitLab recommends for load balancing.
      /-/readiness?all=1  Checks every backend dependency. This is the dangerous one:
                          a slow shared database makes every node report unready at
                          once, the load balancer drains the entire pool, and a
                          degradation becomes an outage. Useful for a monitoring
                          check, never for a load balancer.

    The module refuses /-/health and /health_check because both answer a question that
    is too shallow to gate traffic on.
  EOT
  type        = string
  default     = "/-/readiness"

  validation {
    condition     = !can(regex("^/-/health|^/health_check", var.health_check_path))
    error_message = "/-/health reports only that the application server is running, so a node whose database is gone still passes and keeps receiving traffic. Use /-/readiness."
  }

  validation {
    condition     = !strcontains(var.health_check_path, "all=1")
    error_message = "/-/readiness?all=1 checks shared backend dependencies, so one slow database makes every node report unready at the same moment and the load balancer drains the entire pool. It is a monitoring check, not a target group check. Use /-/readiness."
  }
}

###############################################################################
# Alarm routing
###############################################################################

variable "alarm_topic_arn" {
  description = "Existing SNS topic for alarm notifications. Null creates one."
  type        = string
  default     = null
}

variable "alarm_subscriptions" {
  description = <<-EOT
    protocol => endpoint subscribed to a module-created topic, e.g.
    { email = "platform-oncall@example.com" }.

    Only applies when this module creates the topic. Supplying both this and
    alarm_topic_arn is refused rather than ignored: a caller who sets both would
    otherwise believe the alarms reach someone when nothing is subscribed.
  EOT
  type        = map(string)
  default     = {}

  # The guard belongs here rather than on the subscription resource, because that
  # resource has no instances in exactly the case being guarded against, so a
  # precondition on it could never run.
  validation {
    condition     = length(var.alarm_subscriptions) == 0 || var.alarm_topic_arn == null
    error_message = "alarm_subscriptions applies only to a module-created topic, but alarm_topic_arn was supplied. Subscribe to that topic where it is defined, or drop alarm_topic_arn."
  }
}

###############################################################################
# Disk
###############################################################################

variable "repository_volume_path" {
  description = <<-EOT
    Mount path of the repositories volume, as the CloudWatch agent reports it.

    Disk-full is the most common cause of a self-managed GitLab outage, and repository
    disk usage deserves to be the single most important alarm on the platform. It is
    also entirely preventable given warning.
  EOT
  type        = string
  default     = "/var/opt/gitlab"
}

variable "disk_thresholds" {
  description = <<-EOT
    Percentage-used thresholds for the repository volume.

      ticket  raise a ticket, no page
      warn    warning alert
      page    wake someone up

    Three levels rather than one because the useful property of a disk alarm is lead
    time, not detection.
  EOT

  type = object({
    ticket = optional(number, 70)
    warn   = optional(number, 80)
    page   = optional(number, 90)
  })
  default = {}

  validation {
    condition     = var.disk_thresholds.ticket < var.disk_thresholds.warn && var.disk_thresholds.warn < var.disk_thresholds.page
    error_message = "disk_thresholds must increase: ticket < warn < page."
  }

  validation {
    condition     = var.disk_thresholds.page <= 99
    error_message = "The page threshold must leave headroom to act; 99 percent is already an outage."
  }
}

variable "cloudwatch_agent_installed" {
  description = <<-EOT
    Confirms the CloudWatch agent is installed and publishing to the namespace below.

    EC2 publishes neither memory nor disk-usage metrics on its own. Without the agent
    the disk and memory alarms below reference metrics that will never exist, and since
    every alarm here treats missing data as breaching, they would go to ALARM on the
    first evaluation and page continuously while nothing is wrong. The module refuses
    to create them rather than create alarms that cannot tell you anything.

    The agent also has to be configured to publish the dimension set the alarms match
    on: aggregation_dimensions = [["InstanceId","path"]] for disk and [["InstanceId"]]
    for memory. A default agent config emits disk metrics dimensioned by path, device
    and fstype, which no alarm here would match.
  EOT
  type        = bool
  default     = false
}

variable "disk_metric_dimensions" {
  description = <<-EOT
    Dimension set the disk alarms match on. Empty uses
    { InstanceId = var.instance_id, path = var.repository_volume_path }.

    Set this when the CloudWatch agent publishes a different set. A default agent
    config dimensions disk metrics by path, device and fstype on top of the appended
    InstanceId, and an alarm matches on the exact set or on nothing at all.
  EOT
  type        = map(string)
  default     = {}
}

variable "memory_metric_dimensions" {
  description = "Dimension set the memory alarm matches on. Empty uses { InstanceId = var.instance_id }."
  type        = map(string)
  default     = {}
}

variable "cloudwatch_agent_namespace" {
  description = "Namespace the CloudWatch agent publishes to."
  type        = string
  default     = "CWAgent"
}

###############################################################################
# Sidekiq
###############################################################################

variable "sidekiq_queue_latency_thresholds" {
  description = <<-EOT
    Sidekiq queue latency thresholds, in seconds.

    This is the earliest predictive signal GitLab offers: queue latency typically starts
    climbing 10 to 30 minutes before users notice anything. It is the closest thing to a
    leading indicator on the platform, and the metric most worth paging on before impact
    rather than after.

    Requires GitLab's Prometheus metrics to be shipped to CloudWatch.
  EOT

  type = object({
    warn = optional(number, 30)
    page = optional(number, 300)
  })
  default = {}

  validation {
    condition     = var.sidekiq_queue_latency_thresholds.warn < var.sidekiq_queue_latency_thresholds.page
    error_message = "The warn threshold must be lower than the page threshold."
  }
}

variable "enable_sidekiq_alarms" {
  description = "Create the Sidekiq alarms. Requires GitLab's Prometheus metrics to reach CloudWatch."
  type        = bool
  default     = false
}

variable "gitlab_metrics_namespace" {
  description = "CloudWatch namespace carrying GitLab's own metrics."
  type        = string
  default     = "GitLab"
}

variable "gitlab_metric_dimensions" {
  description = <<-EOT
    Dimensions GitLab's metrics carry once they reach CloudWatch. Empty uses
    { InstanceId = var.instance_id }.

    A CloudWatch alarm matches a metric on its exact dimension set, so this has to
    agree with whatever ships the metrics. Get it wrong and the alarm is not
    approximately right: it matches nothing, and because missing data is treated as
    breaching it pages continuously while the platform is healthy.
  EOT
  type        = map(string)
  default     = {}
}

###############################################################################
# Backups
###############################################################################

variable "backup_bucket_name" {
  description = "S3 bucket holding GitLab backups, used for the freshness alarm. Null disables it."
  type        = string
  default     = null
}

variable "backup_object_prefix" {
  description = "Key prefix the backup job writes under. The request-metrics filter and the freshness alarm are both scoped to it, so an unrelated write elsewhere in the bucket does not read as a successful backup."
  type        = string
  default     = "backups/"
}

variable "backup_max_age_hours" {
  description = <<-EOT
    Hours without a fresh backup object before the freshness alarm fires.

    A failed backup announces nothing. The alarm counts writes under
    backup_object_prefix rather than reading the exit code of the job, so a run
    that "succeeds" while writing nothing is still caught.
  EOT
  type        = number
  default     = 24

  validation {
    condition     = var.backup_max_age_hours >= 1 && var.backup_max_age_hours <= 24
    error_message = "backup_max_age_hours must be between 1 and 24. The alarm's evaluation window is Period x EvaluationPeriods, here the value in hours converted to seconds, and CloudWatch caps that product at 86400."
  }
}

###############################################################################
# Canaries
###############################################################################

variable "canaries" {
  description = <<-EOT
    Synthetic canaries, keyed by name.

    These are the checks that actually prove GitLab works. Instance metrics tell you the
    box is alive; they do not tell you a developer can push. A `git clone` canary is the
    only check that exercises Gitaly, repository storage, authentication and the network
    path in one go, which is the real user journey.

    HTTPS and SSH are separate failure domains: an SSH-only outage is invisible to every
    HTTPS check. Both are worth running.

      artifact_s3_bucket / artifact_s3_key  the canary bundle, built and uploaded
                                            separately (it is application code, not
                                            infrastructure)
      handler                               entry point inside the bundle
      schedule_expression                   rate(...) or cron(...)
  EOT

  type = map(object({
    artifact_s3_bucket  = string
    artifact_s3_key     = string
    handler             = optional(string, "index.handler")
    runtime_version     = optional(string, "syn-nodejs-puppeteer-9.1")
    schedule_expression = optional(string, "rate(5 minutes)")
    timeout_seconds     = optional(number, 60)
    active_tracing      = optional(bool, true)

    # Alarm period. Defaults to the canary's own interval, because a period shorter
    # than the schedule leaves most periods empty and, with missing data treated as
    # breaching, holds the alarm in ALARM while the canary is passing. Set this
    # explicitly for a cron() schedule, which cannot be decomposed here.
    alarm_period_seconds = optional(number)
  }))
  default = {}
}

variable "canary_execution_role_arn" {
  description = "Role Synthetics assumes to run the canaries. Required when canaries are defined."
  type        = string
  default     = null
}

variable "canary_results_bucket" {
  description = "S3 bucket receiving canary artifacts. Required when canaries are defined."
  type        = string
  default     = null
}
