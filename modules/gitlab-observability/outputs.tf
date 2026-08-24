output "alarm_topic_arn" {
  description = "SNS topic alarms publish to."
  value       = local.topic_arn
}

output "health_check_path" {
  description = "Path to configure on the load balancer target group. Never /-/health."
  value       = var.health_check_path
}

output "canary_names" {
  description = "Synthetic canary names, keyed by the logical name given in var.canaries."
  value       = { for k, c in aws_synthetics_canary.this : k => c.name }
}

output "alarm_names" {
  description = "Every alarm this module created, so they can be added to a dashboard or a composite alarm."
  value = concat(
    [aws_cloudwatch_metric_alarm.instance_status.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.canary_failed : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.sidekiq_queue_latency : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.repository_disk : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.memory : a.alarm_name],
    [for a in aws_cloudwatch_metric_alarm.backup_freshness : a.alarm_name],
  )
}

output "coverage_gaps" {
  description = <<-EOT
    What this module is NOT watching, given how it was configured, and why that matters.

    Present because the dangerous state for a monitoring stack is looking complete while
    missing the signal that would have given warning. An empty list here is a claim worth
    making; a populated one is a to-do.
  EOT
  value = compact([
    var.cloudwatch_agent_installed ? "" : "disk and memory: the CloudWatch agent is not installed, and EC2 publishes neither on its own. Disk-full is the most common cause of a self-managed GitLab outage.",
    var.enable_sidekiq_alarms ? "" : "Sidekiq queue latency: the earliest predictive signal available, typically 10-30 minutes ahead of user-visible impact.",
    var.backup_bucket_name == null ? "backup freshness: nothing detects a backup job that silently stopped producing." : "",
    length(var.canaries) == 0 ? "synthetic canaries: no check proves a developer can actually clone. Host metrics only show the box is alive." : "",
  ])
}
