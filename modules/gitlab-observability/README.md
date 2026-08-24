# `gitlab-observability`

Scenario 3. Monitoring for a self-managed GitLab: synthetic canaries, the alarms
that matter, and an explicit statement of what is not being watched.

Design rationale is in [`docs/scenario-3-gitlab-resilience.md`](../../docs/scenario-3-gitlab-resilience.md).
This file is usage.

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

**1. Synthetic canaries.** Instance metrics tell you the box is alive. They do not
tell you a developer can push. A `git clone` canary is the only check that exercises
Gitaly, repository storage, authentication and the network path in one go, which is
the real user journey. Run it over **both** HTTPS and SSH: they are separate failure
domains, and an SSH-only outage is invisible to every HTTPS check.

**2. Sidekiq queue latency.** The earliest predictive signal GitLab offers. It
typically starts climbing 10 to 30 minutes before users notice anything, which makes
it the one metric here worth paging on ahead of impact rather than after it.

**3. Repository disk.** Disk-full is the most common cause of a self-managed GitLab
outage, and it is entirely preventable given warning. Three thresholds (70 ticket,
80 warn, 90 page), because the useful property of a disk alarm is lead time, not
detection.

**4. Host status and backup freshness.** The freshness alarm watches the age of the
backup object rather than the exit code of the job, so a run that "succeeds" while
writing nothing is still caught.

## Two things it refuses

**`/-/health` as a load balancer health check.** GitLab's documentation warns against
this explicitly: the endpoint fails whenever any backend dependency is slow, so a
transient database slowdown pulls every healthy node out of the pool and turns a
degradation into an outage. The load balancer becomes an amplifier of small problems.
Use `/-/readiness`, which is the default.

**Disk and memory alarms without the CloudWatch agent.** EC2 publishes neither metric
on its own. Creating the alarms anyway produces alarms stuck in `INSUFFICIENT_DATA`
forever, which on a dashboard is indistinguishable from healthy. Set
`cloudwatch_agent_installed = true` once the agent is actually running.

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
terraform init && terraform test    # 12 tests, mocked provider, no AWS account
```
