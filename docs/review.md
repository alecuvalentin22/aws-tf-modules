# Adversarial review of the backup module

The module was handed to a second agent briefed as a hostile assessor: find everything
wrong, prioritise silent failures over cosmetics, and flag uncertainty as uncertainty
rather than asserting it. It had Terraform, the test suites and a scratch directory to
write its own throwaway tests in, and it used them — two findings below were confirmed
by tests it wrote to break the module rather than by reading.

This page records what it found and what changed. It is here because the interesting
part of the exercise is not that the module was correct; it is that six of the defects
would have applied cleanly and failed later, in production, with nothing in the apply
output to indicate it.

---

## Fixed

### Blockers

**The deny-delete vault policy denied its own replacement.**
The `Deny` statement used `Principal: "*"` and included `backup:PutBackupVaultAccessPolicy`
and `backup:DeleteBackupVaultAccessPolicy`, with the exemption list empty by default and
not exposed on the parent module at all. The moment it applied, the policy became
unmodifiable and unremovable by the role that created it: the vault could never gain a
new source account or a break-glass exemption, and `terraform destroy` could never
succeed. The `minimal` example's claim that governance mode makes it "safe to destroy
again" was false.

*Fixed:* both actions removed from the deny list — Vault Lock is what provides the
tamper-proof guarantee, and the access policy is documented as the removable layer, which
it now actually is. `enable_deny_delete_policy` and `deny_delete_principals_except` are
exposed on the parent. A `depends_on` edge makes the policy tear down before the lock, so
destroy ordering cannot deadlock on the policy denying `DeleteBackupVaultLockConfiguration`.
Three tests assert the deny list's contents.

**Restore testing selected nothing.**
`protected_resource_conditions` filters the *protected resource* by its own tags. The
code matched `aws:ResourceTag/BackupRule` — a **recovery point** tag, stamped by the plan
onto recovery points and never present on the source volume, instance or table. The
selection matched zero resources. The testing plan ran weekly, tested nothing, reported
success, and manufactured audit evidence for a control that was not running. This was the
module's self-declared flagship control.

*Fixed:* conditioned on `selection_required_tags` — the tags that are actually on the
protected resources, and the same ones the backup selection matches. The comment now
states the right mental model.

**SNS topics were encrypted with a key nothing could publish through.**
`kms_master_key_id = "alias/aws/sns"` is the AWS-*managed* key. Its policy grants only the
account's own IAM principals via `kms:ViaService` and cannot be edited, so
`backup.amazonaws.com`, `events.amazonaws.com` and `cloudwatch.amazonaws.com` could not
obtain `kms:GenerateDataKey*`. Every vault notification, the EventBridge failure rule and
both CloudWatch alarms would have failed with `KMSAccessDeniedException` at delivery time
— invisibly. Nothing surfaces in the apply, the alarm state or the SNS console.

The sharpest edge of it: the staleness alarm is the one control that detects a plan which
has stopped running at all, and it would have been the one guaranteed never to fire.

*Fixed:* a customer managed key per Region whose policy names the three publishing service
principals. Four tests assert both the key policy and the topic policy grant each of them,
and one asserts specifically that `alias/aws/sns` is not used.

### Cross-account permission path

**The source role was never granted KMS on the destination key.**
A key policy granting `arn:aws:iam::<source>:root` **delegates** to that account's IAM; it
does not authorise any principal there. Both sides must allow. The module granted three of
the four required permissions and had no way to express the fourth — every encrypted
cross-account copy would have failed with `AccessDenied` on the destination key, nightly.

*Fixed:* `kms_key_arn_external` added to external destinations and folded into the role's
policy. It is **required**, enforced by a precondition whose message explains the
delegation trap, because an optional field here is a silent failure waiting to happen. The
four-grant path is documented as a table in the module README and asserted end to end.

**The destination key granted an entire external account unconditional access.**
`AllowSourceAccountsToCopyIn` granted the full data plane plus `kms:CreateGrant` on
`Resource: "*"` to `<source>:root` with no conditions. Any principal in the source account
that could get an IAM allow on the key ARN — not just the backup role — could decrypt
everything in the isolated vault and mint persistent grants on its key. That undoes the
entire justification for the separate backup account.

*Fixed:* scoped with `kms:ViaService = backup.<region>.amazonaws.com` and
`kms:CallerAccount`; `CreateGrant` split into its own statement conditioned on
`kms:GrantIsForAWSResource`. Both are asserted.

### Guardrails that could fail open

**A copy destination could impersonate the primary vault.**
The primary vault's lock window was merged into the same map as the copy destinations
under a `"__primary__"` sentinel key, and the destination-key regex permitted that exact
string. A destination so named overwrote the primary window, and the primary vault's
retention check then passed for any value. The reviewer confirmed it with a test: primary
window `[30, 60]`, retention of 5 days, zero violations reported.

*Fixed:* the primary window lives in its own local. The collision is structurally
impossible rather than merely discouraged. Regression test included.

**External destinations skipped the retention check silently.**
Omitting `lock_min_retention_days` / `lock_max_retention_days` meant the destination was
simply not checked, with no warning, no output and nothing in the copy matrix. The
module's headline guarantee was inoperative on the cross-account hop — the destination an
operator has least visibility into and the one most likely to carry a stricter compliance
lock.

*Fixed:* omitting them is now an error unless `acknowledge_unchecked_copy_destinations`
is set, and the `unchecked_copy_destinations` output names them either way. Fail-open with
no signal is the wrong default for a guardrail whose entire value is catching this.

**Restore testing plans listed vaults in other Regions.**
Restore testing is a regional service; one plan in the primary Region cannot select
recovery points from a vault in another. The copies would never have been tested — the
exact assumption restore testing exists to disprove.

*Fixed:* one plan per Region, each covering only the vaults it can reach.

**A partial `copy_retention` override replaced the whole lifecycle.**
`{ delete_after = 2555 }` on a rule with `cold_storage_after = 90` produced a seven-year
copy kept entirely in **warm** storage — roughly an order of magnitude more expensive,
with nothing in the plan to show it. The `complete` example demonstrated both shapes,
which suggests it was known and not guarded.

*Fixed:* overrides merge field by field. The override object's attributes are `optional`
with no default so that "unset" stays distinguishable from "set to false", which is what
makes the merge possible. Both directions tested.

### Audit framework

- **Frequency was hardcoded to daily**, so a plan whose shortest tier is weekly would be
  reported non-compliant forever. A framework that is always red teaches the operator to
  ignore it, which is worse than not deploying one. Now derived from the least frequent
  rule.
- **Vault Lock had no control.** The framework audited the vault *access policy* —
  the removable layer — but not Vault Lock itself, inverting the module's own thesis about
  which control is load-bearing. `BACKUP_RESOURCES_PROTECTED_BY_BACKUP_VAULT_LOCK` added.
- **The cross-Region and cross-account controls were unparameterised**, so they passed for
  a copy to *any* Region or account. Now pinned to the configured destinations.
- **The scope could render more than one tag**, which the ControlScope API does not accept.
  Now derived only where unambiguous, omitted otherwise, with a validation. The consequence
  — that the framework's scope is necessarily wider than the plan's selection, because
  pattern-matched tags cannot be expressed in a scope — is documented rather than hidden.
- **`maxRestoreTime` is in minutes**, which was undocumented and is a 60× difference if
  misread. Now a named variable with the unit in its description.

### Smaller fixes

- **Vault notifications raced the SNS topic policy.** `PutBackupVaultNotifications`
  validates that the topic policy permits `backup.amazonaws.com`, so a cold apply could
  issue it first — a non-deterministic first-apply failure that succeeds on re-run and
  therefore reads as flakiness. Notifications moved to the parent module where they can
  carry the `depends_on`.
- **The role's trust policy used plain `StringEquals` / `ArnLike`.** A plain condition on
  a context key the caller does not populate evaluates to *false*, which would make the
  role unassumable and stop every backup job in the account — silently. Now `IfExists`,
  which keeps the confused-deputy guard where the keys are present without betting the
  whole plan on them always being so. Asserted.
- **The defaults did not satisfy requirement 2.** `selection_required_tags` defaulted to
  `ToBackup=true` with no owner condition, so the module as shipped enforced half of
  "`ToBackup=true` AND `Owner=<owner>`" — reproducing the exact gap it was built to
  prevent. `selection_required_tag_patterns` now defaults to `{ Owner = "*@*" }`.
- **`completion_window == start_window`** was accepted; AWS requires strictly greater.
- **Continuous backup with copy actions** is now an explicit acknowledgement, since
  copying continuous recovery points is only supported for some resource types.
- **`force_destroy`** exposed for throwaway environments.
- **The `complete` example** now lists the out-of-band prerequisites —
  `isCrossAccountBackupEnabled`, same-Organization membership, per-Region resource-type
  opt-in, AWS Config — none of which fail at apply time and all of which are required for
  the topology it demonstrates to actually work.

### Test quality

The reviewer's sharpest observation was that the policy tests passed for the wrong
reason. `a_cross_account_destination_grants_the_source_account` asserted that a vault
policy and a KMS key *existed* — not that either granted anything — while its own comment
claimed to be testing the grants. Every policy in the module was rendered by
`aws_iam_policy_document`, which a mocked provider returns as an empty placeholder, so all
five policies were entirely unverified.

*Fixed:* policies are now built with `jsonencode`, which makes them plain values a test
can decode and assert on. Twenty tests across the two modules now check the rendered
statements, including the full four-grant cross-account path. Several tautological
assertions — ones restating an input map's size — were replaced with assertions on
rendered resource attributes.

---

## Accepted, not fixed

**The IAM role name is account-global.** Two instantiations with the same `name` in one
account collide with `EntityAlreadyExists`. The failure is loud and immediate at apply
time, and the fix — a Region or random suffix — makes the role name unpredictable, which
is worse for a role referenced in cross-account policies. Documented instead.

**`aws_backup_region_settings` will perpetually diff on a partial opt-in map.** AWS
returns the full set of resource types, so an incomplete map re-diffs every plan. The
variable already defaults to `null` with a warning that this setting belongs in the
account baseline, which is the more important point; the exhaustiveness requirement is now
noted in its description.

**`aws_backup_global_settings` has no `region` argument.** Confirmed against the v6.61.0
schema — it is genuinely absent, so the resource lands in the provider's Region rather
than `primary_region`. Harmless for an organisation-wide setting, and there is nothing to
fix in the module. Noted in a comment.

**The framework's scope is wider than the plan's selection.** Resources tagged
`ToBackup=true` with no `Owner` will be reported as unprotected. That finding is correct —
those resources do need an owner — so it is documented rather than suppressed.

---

## Verified, not defects

Several findings were flagged `VERIFY` rather than asserted, which was the right call.
Checked against the provider schema:

- `aws_backup_global_settings` has no `region` attribute — confirmed, and handled above.
- The `aws_backup_framework` control names used are all accepted by the provider.
- `aws_backup_restore_testing_plan` and `aws_backup_restore_testing_selection` exist in
  v6 with the arguments used.

Two remain genuinely open and could only be settled against a live account:

- Whether the account root is exempt from an explicit `Deny` in a Backup vault access
  policy. The lockout half of that finding was fixed regardless, since the
  Terraform-lifecycle problem did not depend on the answer.
- Whether AWS Backup populates `aws:SourceAccount` on its `AssumeRole` call. Mitigated by
  switching to `IfExists`, which is correct either way.

Flagging these as uncertain rather than asserting them was more useful than a confident
guess would have been, in both directions.
