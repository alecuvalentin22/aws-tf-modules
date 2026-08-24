# Scenario 3 — GitLab resilience and monitoring

> GitLab is the core of the software delivery toolchain. It runs today as a single
> Omnibus EC2 instance with two EBS volumes (root, plus projects and artifacts),
> talking to a Multi-AZ RDS database.

---

## Q1 — Weaknesses from a resilience perspective

The starting observation, because it reframes everything else:

**Everything Omnibus bundles except the database runs on that one instance, in one
Availability Zone.** NGINX, Puma, Gitaly, Redis, Sidekiq, the container registry,
Prometheus. So the Multi-AZ spend on RDS currently buys nothing: an AZ failure takes
GitLab down and leaves a perfectly healthy standby database with nothing left to talk
to. The most expensive resilience component in the design is neutralised by the
cheapest one.

### Critical

**1. Single instance, single AZ, no ASG, no load balancer, no tier isolation.**

- One EC2 failure, one bad `apt` upgrade, one full disk = total outage.
- Recovery is a human rebuilding a hand-configured server. RTO is however long that
  takes, which nobody has measured.
- **No isolation between workloads.** A Monday-morning CI burst starves interactive
  users of the same CPU. A Gitaly OOM during a large clone kills Puma and Redis with
  it. There is no bulkhead anywhere.

**2. The repositories EBS volume is the single most dangerous component.**

- EBS is **zonal**. That one volume pins the entire platform to one AZ, no matter what
  is done elsewhere.
- `gp3` durability is roughly **99.8–99.9% annually**. That figure is applied here to
  the volume holding every Git repository the company owns.
- And the subtle one, which is the real risk:

  > **An EBS snapshot and an RDS point-in-time restore are independent timelines.**

  Restoring both together produces **split-brain**: projects that exist in Postgres
  with no repository on disk, merge requests referencing commits that are not there,
  CI pipelines pointing at missing artifacts. GitLab has no reconciliation tool for
  this. It is the most under-appreciated risk in the design, and it only reveals
  itself during an actual disaster — which is the worst possible time to discover it.

**3. Backups are unproven and probably incomplete.**

- No stated RPO or RTO.
- No cross-region copy — a regional event is unrecoverable.
- **No evidence a restore has ever been tested.** An untested backup is a hypothesis.
- And the specific trap: **`gitlab-secrets.json` is routinely excluded from
  `gitlab-backup`**. Without it, a restored database is useless — 2FA secrets, CI/CD
  variables, runner tokens and integration credentials are all encrypted with keys
  held in that file. Teams discover this during their first real restore.

### High

**4. Redis has no HA.** It holds sessions and the Sidekiq queues. Losing it logs
everyone out and drops queued background jobs.

**5. Disk-full is the most common cause of a self-managed GitLab outage.** Repos,
artifacts, LFS, container images, logs and Docker layers all grow on the same volumes,
and EC2 does not publish disk metrics by default (see Q3).

**6. Upgrades require walking required version stops.** GitLab cannot jump arbitrary
versions; the upgrade path has mandatory intermediate versions with background
migrations that must complete between hops. On a single instance every hop is an
outage, and a failed hop has no rollback.

**7. Monitoring runs on the instance it monitors.** When the box dies, the monitoring
dies with it — so the alert that matters most is the one guaranteed not to fire.

**8. Configuration is not reproducible.** A hand-configured Omnibus instance cannot be
rebuilt identically under pressure.

---

## Q2 — Target architecture

Two options, because the honest answer is that full HA is not always the right buy.

### Option A — "Resilient single node" (recommended first step)

The highest return per unit of effort and cost:

```
              Route 53  ──►  ALB (3 AZs)
                               │
                    ┌──────────┴──────────┐
                    │  ASG: min 1 max 1   │   spans 3 AZs
                    │  GitLab Omnibus     │   rebuilt from a golden AMI
                    └──────────┬──────────┘
                               │
        ┌──────────────┬───────┴────────┬──────────────┐
        ▼              ▼                ▼              ▼
   RDS Multi-AZ   ElastiCache      S3 (artifacts,   EFS or EBS
   (+ RDS Proxy)  Redis Multi-AZ    LFS, registry,  (repos only)
                                    uploads, backups)
```

Changes from today:

- **ASG of one across three AZs** — instance failure or AZ failure triggers an
  automatic rebuild in a surviving AZ.
- **Object data to S3** — artifacts, LFS, uploads, the container registry and backups
  move off EBS. This removes most of the disk-full risk and most of the data at risk
  on the zonal volume.
- **ElastiCache Redis, Multi-AZ** — sessions and queues survive an instance rebuild.
- **RDS Proxy** — connection handling across failovers.
- **Golden AMI built in CI** — the instance is reproducible.
- **Monitoring off-instance.**

| | Today | Option A |
| --- | --- | --- |
| RTO | Hours (manual rebuild) | **~10 minutes** (ASG replacement) |
| RPO | Undefined | **~1 hour** |
| AZ failure | Total outage | Automatic recovery |
| Cost | 1× | **~1.6×** |

Git repositories remain the one stateful thing on the instance, so repository recovery
still depends on snapshot restore — but the blast radius has shrunk from "everything"
to "repositories only", and the split-brain risk is contained to a single pair of
timelines rather than four.

### Option B — GitLab 3K reference architecture (full HA)

The smallest architecture GitLab documents as genuinely highly available:

- **Rails/Puma ASG** across 3 AZs behind an ALB
- **Dedicated Sidekiq ASG** — this is the bulkhead that fixes "CI starves interactive
  users"
- **Gitaly Cluster** (Praefect + Postgres) for replicated repository storage
- **ElastiCache Redis** Multi-AZ
- **RDS Multi-AZ** with RDS Proxy
- **S3** for all object storage
- Monitoring hosted off-instance

Cost: **~3–4×** today.

Three honest caveats, because this is where these designs usually go wrong:

- **Praefect is genuinely complex.** GitLab says so in its own documentation. It
  introduces its own Postgres, its own failover semantics and its own failure modes.
  **Sharded Gitaly** — repositories distributed across Gitaly nodes without Praefect —
  is a reasonable intermediate step that removes the single-node bottleneck without
  taking on Praefect's operational burden.
- **Do not put Git repositories on EFS.** GitLab explicitly advises against it; the
  file-locking and latency characteristics cause corruption and severe performance
  problems.
- **Avoid `gp2` entirely.** Its performance is tied to volume size; `gp3` gives
  independent IOPS and throughput at lower cost.

### Recommendation

**Option A now, Option B when the platform's criticality justifies 3–4×.** Option A
removes the AZ single point of failure, makes the RDS Multi-AZ spend meaningful, and
gets RTO from hours to minutes — which is the bulk of the available risk reduction.
It is also a strictly smaller step, and it is on the path to Option B rather than a
detour from it.

### Backup and DR, in both options

This is separate from the architecture and is not optional:

- **`gitlab-backup` for application data** (repos, DB, uploads, artifacts) —
  the supported, internally consistent path.
- **`gitlab-secrets.json` and `/etc/gitlab` backed up separately**, to a different
  location, with restricted access. Without it, everything else is undecryptable.
- **Cross-region copy** of both, so a regional event is survivable.
- **Restore tested on a schedule**, not on request. See the weekly rehearsal in Q4,
  which doubles as the restore test.
- **A stated, agreed RPO and RTO.** Everything above is unfalsifiable without them.

---

## Q3 — Monitoring practices

Ordered by what actually catches user-visible breakage, which is roughly the inverse
of the order these usually get implemented.

### 1. Synthetic canaries — the only checks that prove GitLab works

Instance-level metrics tell you the box is alive. They do not tell you a developer can
push. CloudWatch Synthetics canaries running from outside the instance:

| Canary | Frequency | What it proves |
| --- | --- | --- |
| `git clone` over **HTTPS** | 5 min | Git works end to end, including auth |
| `git clone` over **SSH** | 5 min | The SSH path works — a separate failure domain that HTTPS checks miss entirely |
| Web login | 5 min | Rails, Redis sessions and the database are all healthy |
| API `GET /api/v4/projects` | 1 min | The API layer responds |
| Container registry pull | 15 min | The registry is serving |
| CI pipeline end to end | 30 min | Runners are picking up jobs |

The `git clone` canary is the important one. It is the only check that exercises
Gitaly, the repository storage, authentication and the network path in one go — which
is the actual user journey.

### 2. Health endpoint choice — a real trap

GitLab's documentation **warns explicitly against using `/-/health` (`/health_check`)
for load balancer health checks**. It fails whenever any backend dependency is slow,
so a transient database slowdown pulls every healthy node out of the pool and turns a
degradation into an outage.

| Endpoint | Use |
| --- | --- |
| `/-/readiness` | **ALB target group health check** |
| `/-/liveness` | Process liveness only |
| `/-/health` | **Not for load balancing** |

Getting this wrong makes the load balancer an amplifier of small problems.

### 3. Sidekiq queue latency — the earliest predictive signal available

Sidekiq queue latency typically starts climbing **10–30 minutes before users notice
anything**. It is the closest thing GitLab has to a leading indicator, and it is the
metric most worth paging on before impact.

- Warn at 30s, alarm at 300s.
- Alarm separately on the dead job set growing.
- Alarm on Sidekiq process count dropping below expected.

### 4. The CloudWatch agent is mandatory, not optional

**EC2 publishes neither memory nor disk-usage metrics.** Without the CloudWatch agent
installed and configured, the two most common causes of a GitLab outage are invisible.

**Repository disk usage deserves to be the single most important alarm on the
platform**, because disk-full is the most common self-managed GitLab failure and it is
entirely preventable with warning:

| Threshold | Action |
| --- | --- |
| 70% | Ticket |
| 80% | Warning alert |
| 90% | Page |

Plus memory utilisation, swap usage (a Gitaly OOM precursor) and inode usage — the
last one bites on repositories with very many small files and is missed by
percentage-of-bytes alarms.

### 5. `treat_missing_data = "breaching"` on every critical alarm

The classic single-node monitoring bug, and it is worth being explicit about:

> A dead host stops sending metrics. An alarm that treats missing data as "not
> breaching" goes **green** at exactly the moment the system dies.

Every alarm whose absence of data indicates failure — canaries, host health, backup
freshness, Sidekiq liveness — must treat missing data as breaching. Getting this
backwards produces a monitoring system that is reassuring precisely when it should be
paging.

### 6. Backup freshness

An alarm that fires when no successful backup has completed in 26 hours, with
`treat_missing_data = "breaching"`. Backups fail silently; that is their defining
characteristic.

Alarm on the S3 object's age rather than on the job's exit code, so a job that
"succeeds" while writing nothing is still caught.

### 7. Monitoring must live off the instance

CloudWatch, Synthetics and the alarms all run outside the GitLab host, so that they
survive its death. If a Prometheus/Grafana stack is wanted for GitLab's own detailed
metrics, run it on separate infrastructure (or Amazon Managed Prometheus/Grafana)
scraping the instance — never on it.

### 8. Logs and audit

Ship `production.log`, `gitaly.log`, `sidekiq.log`, `nginx access/error` and the
audit log to CloudWatch Logs with metric filters on 5xx rates and on repeated
authentication failures. The audit log in particular should not live only on a box
that might be replaced by an ASG.

---

## Q4 — Automating the GitLab runbook

The upgrade runbook is the one that matters, because it is the most frequent risky
operation and the one where a mistake is hardest to undo.

### Why a state machine, not a script

GitLab upgrades must traverse **required version stops**, with background migrations
completing between each hop. The path from the current version to the target depends
on the current version, so the automation has to *compute* the path and then walk it,
pausing between hops until migrations drain. That is a state machine with waits,
retries and conditional branches — a shell script that models it will be wrong.

**AWS Step Functions**, with the gates below. The gates are what make it safe; the
automation is just what makes it repeatable.

```
  ┌─────────────────────────────────────────────────────────────┐
  │ 1. PRE-FLIGHT                                               │
  │    - current version, target version                        │
  │    - compute the required upgrade path                      │
  │    - ANY pending background migration  ──► ABORT            │
  │    - disk space sufficient?            ──► ABORT            │
  │    - health checks green?              ──► ABORT            │
  ├─────────────────────────────────────────────────────────────┤
  │ 2. BACKUP GATE  (hard gate — no skip flag exists)           │
  │    - gitlab-backup create                                   │
  │    - back up gitlab-secrets.json + /etc/gitlab              │
  │    - VERIFY the artifacts exist and are non-empty           │
  │    - copy cross-region                                      │
  ├─────────────────────────────────────────────────────────────┤
  │ 3. DRAIN                                                    │
  │    - deregister from the ALB target group                   │
  │    - pause runners, let in-flight Sidekiq jobs finish        │
  ├─────────────────────────────────────────────────────────────┤
  │ 4. UPGRADE ONE HOP (blue/green)                             │
  │    - launch a new instance from the new AMI                 │
  │    - EXACTLY ONE node runs migrations                       │
  │    - wait for background migrations to drain                │
  ├─────────────────────────────────────────────────────────────┤
  │ 5. POST-CHECKS                                              │
  │    - /-/readiness green                                     │
  │    - gitlab-rake gitlab:check                               │
  │    - canaries pass: clone over HTTPS and SSH, web login     │
  │    - FAIL ──► ROLLBACK                                      │
  ├─────────────────────────────────────────────────────────────┤
  │ 6. MORE HOPS?  ──yes──► back to 3                           │
  │              ──no───► register in ALB, resume runners       │
  └─────────────────────────────────────────────────────────────┘
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
3. It continuously validates that the backup — including `gitlab-secrets.json` — is
   actually restorable, rather than merely present.

A restore procedure that has not run in the last week is a procedure of unknown
status.

### Configuration and the rest of the runbook

- **Configuration as code.** `/etc/gitlab/gitlab.rb` rendered from a template, applied
  by Ansible or user-data. No hand edits — the instance must be reproducible, which
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

| Question | Answer in one line |
| --- | --- |
| Q1 Weaknesses | Everything except the DB is on one instance in one AZ, which neutralises the Multi-AZ RDS; the zonal repository volume pins the platform and its snapshot timeline diverges from the RDS timeline, giving split-brain on restore; backups are untested, not copied cross-region, and probably exclude `gitlab-secrets.json` |
| Q2 Target | "Resilient single node" first — ASG-of-one across 3 AZs, object data on S3, ElastiCache, RDS Proxy: RTO hours → ~10 min for ~1.6× cost. GitLab 3K reference architecture for full HA at 3–4×, with sharded Gitaly as an intermediate step because Praefect is genuinely complex |
| Q3 Monitoring | Synthetic `git clone` canaries over HTTPS and SSH are the only checks that prove Git works; use `/-/readiness` not `/-/health` for the load balancer; Sidekiq queue latency is the earliest predictive signal; the CloudWatch agent is mandatory for memory and disk; `treat_missing_data = "breaching"` on everything critical |
| Q4 Automation | Step Functions that compute and walk the required upgrade path, gated on pending migrations, a verified backup including secrets, a drain, one-node migrations, real post-checks and a defined rollback — rehearsed weekly by restoring production into staging, which doubles as the missing restore test |
