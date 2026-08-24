# `gitlab-observability`

Scenario 3. Monitoring for a self-managed GitLab: synthetic canaries, the alarms
that matter, and an explicit statement of what is not being watched.

The reasoning behind these choices is in
[`docs/scenario-3-gitlab-resilience.md`](../../docs/scenario-3-gitlab-resilience.md).

## Usage

```hcl
module "gitlab_monitoring" {
  source = "./modules/gitlab-observability"

  name        = "gitlab"
  instance_id = "i-0123456789abcdef0"
  base_url    = "https://gitlab.example.com"

  cloudwatch_agent_installed = true
  enable_sidekiq_alarms      = true
  backup_bucket_name         = "gitlab-backups"

  canaries = {
    clone_https = { artifact_s3_bucket = "canary-artifacts", artifact_s3_key = "clone-https.zip" }
    clone_ssh   = { artifact_s3_bucket = "canary-artifacts", artifact_s3_key = "clone-ssh.zip" }
    web_login   = { artifact_s3_bucket = "canary-artifacts", artifact_s3_key = "web-login.zip" }
  }
  canary_execution_role_arn = aws_iam_role.canary.arn
  canary_results_bucket     = "canary-results"

  alarm_subscriptions = { email = "platform-oncall@example.com" }
}
```

Canary bundles are application code and are built and uploaded separately, so the
module takes an S3 location rather than packaging them.

## What it watches, in order of what actually catches breakage

1. Synthetic canaries. Instance metrics establish that the box is alive. They do
not establish that a developer can push. A `git clone` canary is the only check that exercises
Gitaly, repository storage, authentication and the network path in one go, which is
the real user journey. Run it over **both** HTTPS and SSH: they are separate failure
domains, and an SSH-only outage is invisible to every HTTPS check.

2. Sidekiq queue latency. The earliest predictive signal GitLab offers. It
typically starts climbing 10 to 30 minutes before users notice anything, which makes
it the one metric here worth paging on ahead of impact rather than after it.

3. Repository disk. Disk-full is the most common cause of a self-managed GitLab
outage, and it is entirely preventable given warning. Three thresholds (70 ticket,
80 warn, 90 page), because the useful property of a disk alarm is lead time, not
detection.

4. Host status and backup freshness. The freshness alarm counts writes under the
backup prefix rather than reading the exit code of the job, so a run that
"succeeds" while writing nothing is still caught.

### Why the backup alarm is not on `NumberOfObjects`

That is the obvious metric and it cannot answer the question. `AWS/S3`
`NumberOfObjects` is a storage metric: published once a day, counting every object
in the bucket. Once a single backup exists it reports the same healthy number
forever, so an alarm on it detects an empty bucket and nothing else. It also
tempts a period longer than the 86400 seconds CloudWatch accepts, which fails at
apply time.

S3 request metrics have one-minute resolution and can be scoped to a prefix.
`PutRequests` summed over the window, with `FilterId` pointing at a filter on the
backup prefix, answers what was actually being asked. It carries a per-request
metrics charge on that prefix.

## Two things it refuses

`/-/health` as a load balancer health check. It is the *shallow* endpoint: it
reports that the application server is running and nothing more, so a node whose
database has gone away still passes and keeps receiving traffic. `/-/readiness` is
the one GitLab recommends for load balancing, and it is the default here.

The opposite mistake is worth naming in the same breath, because it is what people
reach for after learning the first one. `/-/readiness?all=1` checks every shared
backend dependency, so a single slow database makes every node report unready at
once and the load balancer drains the whole pool. That endpoint belongs in a
monitoring check, never in a target group.

This module creates no load balancer, so the value is validated and re-exported for
the caller's target group rather than attached to anything here.

Disk and memory alarms without the CloudWatch agent. EC2 publishes neither metric
on its own. The usual objection is that such an alarm sits in `INSUFFICIENT_DATA`
forever, but that is not what happens here: every alarm in this module treats
missing data as breaching, so an alarm on a metric nobody publishes goes to `ALARM`
on its first evaluation and pages continuously while nothing is wrong. That is
worse than a silent gap, because it is how a team learns to ignore the alarm that
later matters. Set `cloudwatch_agent_installed = true` once the agent is running.

The same trap applies one level down, to the *dimensions*. CloudWatch matches an
alarm on its exact dimension set, and a default agent config publishes
`disk_used_percent` under `path`, `device` and `fstype` as well as `InstanceId`.
Either configure the agent with
`aggregation_dimensions = [["InstanceId","path"]]`, or set `disk_metric_dimensions`
to whatever it does publish.

## Silence is a failure mode

Every alarm here whose absence of data indicates failure uses
`treat_missing_data = "breaching"`, and a test asserts it for each one.

The inverse is the classic single-node monitoring bug: a dead host stops publishing
metrics, so an alarm treating missing data as "not breaching" goes **green** at
exactly the moment the platform dies. It is reassuring precisely when it should be
paging.

## `coverage_gaps`

The module outputs what it is *not* watching, given how it was configured:

```
coverage_gaps = [
  "disk and memory: the CloudWatch agent is not installed, and EC2 publishes neither on its own...",
  "Sidekiq queue latency: the earliest predictive signal available...",
]
```

The dangerous state for a monitoring stack is looking complete while missing the
signal that would have given warning. An empty list is a claim worth making; a
populated one is a to-do rather than a surprise during an incident.

## Tests

```bash
terraform init && terraform test    # 20 tests, mocked provider, no AWS account
```
