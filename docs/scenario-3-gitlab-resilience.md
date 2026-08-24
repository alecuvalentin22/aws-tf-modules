# Scenario 3 - GitLab resilience and monitoring

> GitLab is the core of the software delivery toolchain. It runs today as a single
> Omnibus EC2 instance with two EBS volumes (root, plus projects and artifacts),
> talking to a Multi-AZ RDS database.

---

The monitoring practices in Q3 are implemented in
[`modules/gitlab-observability`](../modules/gitlab-observability): synthetic canaries,
the alarms that matter, `treat_missing_data = "breaching"` on everything whose silence
indicates failure, and an output naming whatever the configuration leaves unwatched.

---

## Q1 - Weaknesses from a resilience perspective

The starting observation, because it reframes everything else:

**Everything Omnibus bundles except the database runs on that one instance, in one
Availability Zone.** NGINX, Puma, Gitaly, Redis, Sidekiq, the container registry,
Prometheus. So the Multi-AZ spend on RDS currently buys nothing: an AZ failure takes
GitLab down and leaves a perfectly healthy standby database with nothing left to talk
to. The most expensive resilience component in the design is neutralised by the
cheapest one.

### Critical

1. Single instance, single AZ, no ASG, no load balancer, no tier isolation.

- One EC2 failure, one bad `apt` upgrade, one full disk = total outage.
- Recovery is a human rebuilding a hand-configured server. RTO is however long that
  takes, which nobody has measured.
- **No isolation between workloads.** A Monday-morning CI burst starves interactive
  users of the same CPU. A Gitaly OOM during a large clone kills Puma and Redis with
  it. There is no bulkhead anywhere.

2. The repositories EBS volume is the single most dangerous component.

- EBS is **zonal**. That one volume pins the entire platform to one AZ, no matter what
  is done elsewhere.
- `gp3` durability is roughly **99.8-99.9% annually**. That figure is applied here to
  the volume holding every Git repository the company owns.
- And the subtle one, which is the real risk:

  > **An EBS snapshot and an RDS point-in-time restore are independent timelines.**

  Restoring both together produces **split-brain**: projects that exist in Postgres
  with no repository on disk, merge requests referencing commits that are not there,
  CI pipelines pointing at missing artifacts. GitLab has no reconciliation tool for
  this. It is the most under-appreciated risk in the design, and it only reveals
  itself during an actual disaster, which is the worst possible time to discover it.

3. Backups are unproven and probably incomplete.

- No stated RPO or RTO.
- No cross-region copy - a regional event is unrecoverable.
- **No evidence a restore has ever been tested.**
- And the specific trap: **`gitlab-secrets.json` is routinely excluded from
  `gitlab-backup`**. Without it a restored database is useless: 2FA secrets, CI/CD
  variables, runner tokens and integration credentials are all encrypted with keys
  held in that file. Teams find this out during their first real restore.

### High

Redis has no HA. It holds sessions and the Sidekiq queues, so losing it logs everyone
out and drops queued background jobs. Disk-full is the most common cause of a
self-managed GitLab outage, and everything grows on the same volumes: repos, artifacts,
LFS, container images, logs, Docker layers. EC2 publishes no disk metric by default, so
nobody sees it coming (see Q3).

Upgrades are their own problem. GitLab cannot jump arbitrary versions, so the path has
mandatory intermediate stops with background migrations that must drain between hops.
On a single instance every hop is an outage and a failed hop has no rollback.

Two smaller ones. Monitoring runs on the instance it monitors, so when the box dies the
alert that matters most is the one guaranteed not to fire. And a hand-configured Omnibus
instance cannot be rebuilt identically under pressure, which is what recovery actually
requires.

---

## Q2 - Target architecture

Two options, because the honest answer is that full HA is not always the right buy.

### Option A - "Resilient single node" (recommended first step)

The highest return per unit of effort and cost:

```
              Route 53  -->  ALB (3 AZs)
                               |
                    +----------+----------+
                    |  ASG: min 1 max 1   |   spans 3 AZs
                    |  GitLab Omnibus     |   rebuilt from a golden AMI
                    +----------+----------+
                               |
        +--------------+-------+--------+--------------+
        v              v                v              v
   RDS Multi-AZ   ElastiCache      S3 (artifacts,   EBS gp3
   (+ RDS Proxy)  Redis Multi-AZ    LFS, registry,  (repos only)
                                    uploads, backups)
```

Changes from today:

- **ASG of one across three AZs** - instance failure triggers an automatic rebuild.
  AZ failure relaunches too, with the repository-volume caveat below.
- **Object data to S3** - artifacts, LFS, uploads, the container registry and backups
  move off EBS. This removes most of the disk-full risk and most of the data at risk
  on the zonal volume.
- **ElastiCache Redis, Multi-AZ** - sessions and queues survive an instance rebuild.
- **RDS Proxy** - connection handling across failovers.
- **Golden AMI built in CI** - the instance is reproducible.
- **Monitoring off-instance.**

| | Today | Option A |
| --- | --- | --- |
| RTO | Hours (manual rebuild) | **~10 minutes** (ASG replacement) |
| RPO | Undefined | **~1 hour** |
| AZ failure | Total outage | ASG relaunches, but see the caveat below |
| Cost | 1x | **~1.6x** |

One caveat has to be stated plainly, because it is the limit of this option. Git
repositories stay on a zonal EBS volume, so on an AZ failure the ASG relaunches in a
surviving AZ and **cannot attach that volume**. Recovery there is snapshot-restore time,
not ten minutes. The ten-minute figure holds for instance failure inside a healthy AZ,
which is the more common event, and the blast radius has shrunk from "everything" to
"repositories only" because the object data has moved to S3.

Getting AZ failure down to minutes as well means replicated repository storage, which is
Option B. And do not reach for EFS to work around it: GitLab advises against EFS for
repositories, and the file-locking and latency behaviour causes corruption under load.

### Option B - GitLab 3K reference architecture (full HA)

The smallest architecture GitLab documents as genuinely highly available:

- **Rails/Puma ASG** across 3 AZs behind an ALB
- **Dedicated Sidekiq ASG** - this is the bulkhead that fixes "CI starves interactive
  users"
- **Gitaly Cluster** (Praefect + Postgres) for replicated repository storage
- **ElastiCache Redis** Multi-AZ
- **RDS Multi-AZ** with RDS Proxy
- **S3** for all object storage
- Monitoring hosted off-instance

Cost: **~3-4x** today.

Three honest caveats, because this is where these designs usually go wrong:

- **Praefect is genuinely complex.** GitLab says so in its own documentation. It
  introduces its own Postgres, its own failover semantics and its own failure modes.
  **Sharded Gitaly** - repositories distributed across Gitaly nodes without Praefect -
  is a reasonable intermediate step that removes the single-node bottleneck without
  taking on Praefect's operational burden.
- **Do not put Git repositories on EFS.** GitLab explicitly advises against it; the
  file-locking and latency characteristics cause corruption and severe performance
  problems.
- **Avoid `gp2` entirely.** Its performance is tied to volume size; `gp3` gives
  independent IOPS and throughput at lower cost.

### Recommendation

Option A now, Option B when the platform's criticality justifies 3-4x. Option A
removes the AZ single point of failure, makes the RDS Multi-AZ spend meaningful, and
gets RTO from hours to minutes, which is the bulk of the available risk reduction.
It is also a strictly smaller step, and it is on the path to Option B rather than a
detour from it.

### Backup and DR, in both options

This is separate from the architecture and is not optional:

- **`gitlab-backup` for application data** (repos, DB, uploads, artifacts) -
  the supported, internally consistent path.
- **`gitlab-secrets.json` and `/etc/gitlab` backed up separately**, to a different
  location, with restricted access. Without it, everything else is undecryptable.
- **Cross-region copy** of both, so a regional event is survivable.
- **Restore tested on a schedule**, not on request. See the weekly rehearsal in Q4,
  which doubles as the restore test.
- **A stated, agreed RPO and RTO.** Everything above is unfalsifiable without them.

---

## Q3 - Monitoring practices

Ordered by what actually catches user-visible breakage, which is roughly the inverse
of the order these usually get implemented.

### 1. Synthetic canaries - the only checks that prove GitLab works

Instance-level metrics tell you the box is alive. They do not tell you a developer can
push. CloudWatch Synthetics canaries running from outside the instance:

| Canary | Frequency | What it proves |
| --- | --- | --- |
| `git clone` over **HTTPS** | 5 min | Git works end to end, including auth |
| `git clone` over **SSH** | 5 min | The SSH path works - a separate failure domain that HTTPS checks miss entirely |
| Web login | 5 min | Rails, Redis sessions and the database are all healthy |
| API `GET /api/v4/projects` | 1 min | The API layer responds |
| Container registry pull | 15 min | The registry is serving |
| CI pipeline end to end | 30 min | Runners are picking up jobs |

The `git clone` canary is the important one. It is the only check that exercises
Gitaly, the repository storage, authentication and the network path in one go, which
is the actual user journey.

### 2. Health endpoint choice - a real trap

The three endpoints check different depths, and picking on the wrong axis is how a
load balancer turns a small problem into an outage.

| Endpoint | What it checks | Use for |
| --- | --- | --- |
| `/-/liveness` | The application server is up | Process liveness |
| `/-/health` | The application server is up. It does **not** verify the database or other services | A shallow check; will keep a node in rotation that cannot serve |
| `/-/readiness` | The application is ready to serve | **ALB target group health check** |
| `/-/readiness?all=1` | Readiness plus every dependent service | Deep diagnostics, **not** the load balancer |

Use `/-/readiness` for the target group. The trap is `?all=1`: it probes every
dependency, so a transient database slowdown fails the check on every healthy node at
once and the load balancer drains the entire pool. The failure is correlated by
construction, which is exactly what you do not want from a health check.

`/-/health` errs the other way. It will report healthy on a node whose database
connection is gone, so traffic keeps arriving at an instance that cannot answer.

### 3. Sidekiq queue latency - the earliest predictive signal available

Sidekiq queue latency typically starts climbing **10-30 minutes before users notice
anything**. It is the closest thing GitLab has to a leading indicator, and it is the
metric most worth paging on before impact.

- Warn at 30s, alarm at 300s.
- Alarm separately on the dead job set growing.
- Alarm on Sidekiq process count dropping below expected.

### 4. The CloudWatch agent is mandatory, not optional

EC2 publishes neither memory nor disk-usage metrics. Without the CloudWatch agent
installed and configured, the two most common causes of a GitLab outage are invisible.

**Repository disk usage deserves to be the single most important alarm on the
platform**, because disk-full is the most common self-managed GitLab failure and it is
entirely preventable with warning:

| Threshold | Action |
| --- | --- |
| 70% | Ticket |
| 80% | Warning alert |
| 90% | Page |

Plus memory utilisation, swap usage (a Gitaly OOM precursor) and inode usage, the
last one bites on repositories with very many small files and is missed by
percentage-of-bytes alarms.

### 5. `treat_missing_data = "breaching"` on every critical alarm

The classic single-node monitoring bug, and it is worth being explicit about:

> A dead host stops sending metrics. An alarm that treats missing data as "not
> breaching" goes **green** at exactly the moment the system dies.

Every alarm whose absence of data indicates failure, canaries, host health, backup
freshness, Sidekiq liveness, must treat missing data as breaching. Getting this
backwards produces a monitoring system that is reassuring precisely when it should be
paging.

### 6. Backup freshness

An alarm that fires when nothing has been written under the backup prefix within
the backup window, with `treat_missing_data = "breaching"`. Backups fail silently;
that is their defining characteristic. Watch what arrived in the bucket rather than
the job's exit code, so a run that "succeeds" while writing nothing is still caught.

The metric matters here. `AWS/S3 NumberOfObjects` is the obvious choice and it is
the wrong one: it is a storage metric, published once a day, counting every object
in the bucket, so once a single backup exists it reports the same healthy number
forever. An alarm on it detects an empty bucket and nothing else.

S3 **request metrics** have one-minute resolution and can be scoped to a prefix.
`PutRequests` summed over the window, with the `FilterId` dimension pointing at a
filter on the backup prefix, answers the question actually being asked. Note also
that CloudWatch caps an alarm period at 86400 seconds, so a 26-hour window has to
become a 24-hour one or move to a metric maths expression over shorter periods.

### 7. Monitoring must live off the instance

CloudWatch, Synthetics and the alarms all run outside the GitLab host, so that they
survive its death. If a Prometheus/Grafana stack is wanted for GitLab's own detailed
metrics, run it on separate infrastructure (or Amazon Managed Prometheus/Grafana)
scraping the instance, never on it.

### 8. Logs and audit

Ship `production.log`, `gitaly.log`, `sidekiq.log`, `nginx access/error` and the
audit log to CloudWatch Logs with metric filters on 5xx rates and on repeated
authentication failures. The audit log in particular should not live only on a box
that might be replaced by an ASG.

---

## Q4 - Automating the GitLab runbook

The upgrade runbook is the one that matters, because it is the most frequent risky
operation and the one where a mistake is hardest to undo.

### Why a state machine, not a script

GitLab upgrades must traverse **required version stops**, with background migrations
completing between each hop. The path from the current version to the target depends
on the current version, so the automation has to *compute* the path and then walk it,
pausing between hops until migrations drain. That is a state machine with waits,
retries and conditional branches, a shell script that models it will be wrong.

AWS Step Functions, with the gates below. The gates are what make it safe; the
automation is just what makes it repeatable.

```
  +-------------------------------------------------------------+
  | 1. PRE-FLIGHT                                               |
  |    - current version, target version                        |
  |    - compute the required upgrade path                      |
  |    - ANY pending background migration  --> ABORT            |
  |    - disk space sufficient?            --> ABORT            |
  |    - health checks green?              --> ABORT            |
  +-------------------------------------------------------------+
  | 2. BACKUP GATE  (hard gate - no skip flag exists)           |
  |    - gitlab-backup create                                   |
  |    - back up gitlab-secrets.json + /etc/gitlab              |
  |    - VERIFY the artifacts exist and are non-empty           |
  |    - copy cross-region                                      |
  +-------------------------------------------------------------+
  | 3. DRAIN                                                    |
  |    - deregister from the ALB target group                   |
  |    - pause runners, let in-flight Sidekiq jobs finish        |
  +-------------------------------------------------------------+
  | 4. UPGRADE ONE HOP (blue/green)                             |
  |    - launch a new instance from the new AMI                 |
  |    - EXACTLY ONE node runs migrations                       |
  |    - wait for background migrations to drain                |
  +-------------------------------------------------------------+
  | 5. POST-CHECKS                                              |
  |    - /-/readiness green                                     |
  |    - gitlab-rake gitlab:check                               |
  |    - canaries pass: clone over HTTPS and SSH, web login     |
  |    - FAIL --> ROLLBACK                                      |
  +-------------------------------------------------------------+
  | 6. MORE HOPS?  --yes--> back to 3                           |
  |              --no---> register in ALB, resume runners       |
  +-------------------------------------------------------------+
```

### The gates, and why each exists

| Gate | Prevents |
| --- | --- |
| Pending-migration check blocks the next hop | The most common cause of a corrupted GitLab upgrade |
| Backup gate with **verification**, not just execution | Upgrading with a backup that silently wrote nothing |
| Secrets backed up alongside the database | A restore that produces an undecryptable instance |
| Exactly one node runs migrations | Concurrent migrations corrupting the schema |
| Post-checks include a real `git clone` | "The service is up" while Git is broken |
| Defined rollback per hop | A half-upgraded platform with no way back |

### Rehearse it weekly

**Restore the previous night's production backup into a staging environment every
week, using the same state machine.**

This is the highest-value single practice available here, because it does three jobs
at once:

1. It rehearses the upgrade path on real data before it runs in production.
2. It **is** the restore test that nobody currently performs (Q1.3).
3. It proves the backup, `gitlab-secrets.json` included, is actually restorable rather
   than merely present.

A restore procedure that has not run in the last week is a procedure of unknown
status.

### Configuration and the rest of the runbook

- **Configuration as code.** `/etc/gitlab/gitlab.rb` rendered from a template, applied
  by Ansible or user-data. No hand edits, the instance must be reproducible, which
  is also what makes the ASG in Q2 safe.
- **Golden AMI built in CI** on every GitLab release, with the upgrade path validated
  in staging before the AMI is promoted.
- **Runner scaling** on the Sidekiq queue depth from Q3.
- **Certificate renewal, log rotation, cleanup of stale artifacts and registry
  garbage collection** as scheduled EventBridge jobs, each with a failure alarm.
- **Every runbook step emits a CloudWatch metric and a log line**, so the automation
  is itself observable and a failed hop is attributable.

---

## Summary

The weakness that reframes the rest is that everything except the database runs on one
instance in one Availability Zone, which means the Multi-AZ spend on RDS currently buys
nothing. The repository volume is worse: EBS is zonal, so it pins the platform, and its
snapshot timeline is independent of the RDS point-in-time timeline, so restoring both
together produces split-brain that only reveals itself during a real disaster. Backups
have no stated RPO or RTO, no cross-region copy, no evidence of a tested restore, and
probably exclude `gitlab-secrets.json`, without which a restored database is undecryptable.

For the target, take the resilient single node first: an ASG of one across three AZs,
object data on S3, ElastiCache for Redis, RDS Proxy. That brings RTO from hours to about
ten minutes for roughly 1.6x the cost, and it removes the AZ single point of failure that
makes the current RDS spend pointless. GitLab's 3K reference architecture is the full HA
answer at 3-4x, with sharded Gitaly as a sensible intermediate step, because Praefect is
complex enough that GitLab says so in its own documentation.

On monitoring, synthetic `git clone` canaries over both HTTPS and SSH are the only checks
that prove Git actually works. Use `/-/readiness` for the load balancer: `/-/health`
is too shallow and keeps a node that cannot serve in rotation, while `?all=1` is too
deep and drains every node at once on one slow dependency. Sidekiq queue
latency is the earliest predictive signal available. The CloudWatch agent is mandatory,
since EC2 publishes neither memory nor disk. And every critical alarm needs
`treat_missing_data = "breaching"`, because a dead host stops publishing and the alarm
would otherwise go green as the platform dies.

The runbook worth automating is the upgrade, as a state machine that computes and walks
the required version path rather than a script. The gates are what make it safe: a
pending-migration check, a verified backup including the secrets file, a drain, exactly
one node running migrations, real post-checks, and a defined rollback. Rehearse it weekly
by restoring the previous night's production backup into staging, which doubles as the
restore test nobody currently performs.
