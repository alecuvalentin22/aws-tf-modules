# Runbook - restoring from the backup policy

For the operator on call. Assumes the module in
[`modules/backup-policy`](../modules/backup-policy) is deployed.

The first section is the one to read at 03:00. Everything after it is context.

---

## 0. Decide which copy to restore from

Three copies exist and they are not interchangeable. Restoring from the wrong one
costs hours.

| Copy | Use it when | Cost of using it |
| --- | --- | --- |
| **Primary vault** (local Region) | Default. Anything that is not a Region-wide or account-wide event | Fastest - same Region, no transfer |
| **Cross-Region copy** | The primary Region is impaired, or the primary vault's recovery point is corrupt | Inter-Region transfer; restore into the secondary Region |
| **Cross-account copy** (isolated account) | The prod account is compromised, or its recovery points have been deleted or tampered with | Slowest. Requires access to the backup account, and the restore target must be somewhere the attacker cannot reach |

**If you are here because of ransomware or a suspected account compromise, go
straight to the cross-account copy** and do not restore into the compromised
account. The other two copies are reachable by the credentials that caused the
incident.

If the monthly tier is involved and the recovery point is older than 90 days it is
in **cold storage**: the restore will take hours rather than minutes. Start it
first, then continue triage.

---

## 1. Find the recovery point

```bash
PLAN=platform-backup
VAULT=$(terraform output -raw -state=... primary_vault_arn 2>/dev/null || echo "$PLAN-primary")

# What is in the vault, newest first.
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name "$VAULT" \
  --query 'sort_by(RecoveryPoints,&CreationDate)[-20:].[RecoveryPointArn,ResourceType,CreationDate,Status]' \
  --output table

# Narrow to one resource.
aws backup list-recovery-points-by-resource \
  --resource-arn arn:aws:rds:eu-central-1:111111111111:db:orders \
  --output table
```

Each recovery point carries a `BackupRule` tag naming the tier that produced it
(`daily`, `weekly`, `monthly`). That is how you tell a 35-day point from a
seven-year one when the timestamps alone are ambiguous.

Check `Status` is `COMPLETED`. A `PARTIAL` recovery point will restore, and will
restore incompletely.

---

## 2. Restore

```bash
aws backup start-restore-job \
  --recovery-point-arn "$RP_ARN" \
  --iam-role-arn "$(terraform output -raw backup_role_arn)" \
  --metadata file://restore-metadata.json \
  --resource-type RDS
```

`--metadata` is resource-type specific and is the step that most often fails.
Get the correct shape from the recovery point itself rather than writing it by hand:

```bash
aws backup get-recovery-point-restore-metadata \
  --backup-vault-name "$VAULT" \
  --recovery-point-arn "$RP_ARN"
```

Then edit only what must change, typically the target identifier, so the restore
does not collide with the resource you are recovering from.

Restore to a new resource, never over the original. Keeping the damaged
resource intact preserves the evidence, and gives you something to fall back to if
the restore turns out worse than what you have.

Watch it:

```bash
aws backup describe-restore-job --restore-job-id "$JOB_ID"
```

---

## 3. Cross-account restore

Run **from the backup account**, not from prod.

```bash
# In the backup account:
aws backup list-recovery-points-by-backup-vault \
  --backup-vault-name platform-backup-isolated \
  --output table
```

The recovery point is encrypted with the backup account's own key, so the restore
must run there, and the restored resource lands there. Moving it back to a
production account is a second, separate step, and during an active compromise it
should not happen until the prod account is known clean.

If this fails with `AccessDenied` on KMS, the cause is almost always the key policy
rather than the vault policy. See [ADR-0004](../docs/adr/0004-module-composition-and-account-boundaries.md).

---

## 4. Verify before declaring recovery

A restore job reporting `COMPLETED` means AWS created a resource. It does not mean
the data is usable.

- **RDS**: connect, run a row count against the largest table, confirm the newest
  record's timestamp matches the expected RPO.
- **DynamoDB**: item count, and spot-check a known partition key.
- **S3**: object count and a checksum on a known object.
- **EBS**: attach, mount, verify the filesystem is clean.

Then compare the newest data present against the recovery point's creation time.
The gap is your actual RPO for this incident, and it belongs in the incident record
whether or not it met target.

---

## Why the module makes some of this easier

- **`effective_copy_matrix`** output tells you which tier copied where and with what
  retention, without reading the plan.
- **Recovery points are tagged with `BackupRule`**, so the tier is visible in a
  listing.
- **Restore testing** runs weekly against the primary vault and every managed copy.
  Its history is the best available evidence of what your RTO actually is, before
  you need it. Check it in the AWS Backup console under Restore testing.

---

## Things that will bite you

A compliance-mode Vault Lock refuses deletion. If you are trying to clean up
after a test restore and the recovery points will not delete, that is the lock
working as designed. Wait out the retention. `terraform destroy` will also fail
against such a vault while it holds recovery points.

Cold storage restores are slow. The monthly tier transitions after 90 days.
Anything older restores in hours. Start it before you finish triage.

A restore is a privileged operation - it creates resources. The module's role
carries the AWS restore policies, but a separate restore role
(`restore_testing_iam_role_arn`) is worth having so that routine backup permissions
do not include the ability to materialise a copy of production anywhere.

Continuous (PITR) recovery points restore to a point in time, not to a snapshot.
The metadata shape differs, and the restorable window is at most 35 days.

---

## After the incident

1. Record the actual RPO and RTO measured, against target.
2. If the restore metadata needed hand-editing, capture the working version here.
3. If a copy was unusable, that is a **finding against the backup policy**, not
   against the person restoring, check whether restore testing was covering that
   resource type, and add it if not.
