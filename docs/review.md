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
principals. Three tests cover it: one on the key policy, one on the topic policy, and one
asserting specifically that `alias/aws/sns` is not used.

### Cross-account permission path

**The source role was never granted KMS on the destination key.**
A key policy granting `arn:aws:iam::<source>:root` **delegates** to that account's IAM; it
does not authorise any principal there. Both sides must allow. The module granted three of
the four required permissions and had no way to express the fourth — every encrypted
cross-account copy would have failed with `AccessDenied` on the destination key, nightly.

*Fixed:* `kms_key_arn_external` added to external destinations and folded into the role's
policy. It is **required** whenever this module builds the backup role, enforced by a
precondition whose message explains the delegation trap, because an optional field here is
a silent failure waiting to happen. The four-grant path is documented as a table in the
module README, and asserted on both sides — grants 1–2 in the root module's suite, 3–4 in
the vault module's. Nothing asserts the ARNs match across the account boundary; that is
what the governance-mode restore rehearsal is for.

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
statements, including both halves of the cross-account path.

Several assertions that restate an input map's size remain — `length(local.managed_regions) == 2`
and similar. They are cheap structural checks rather than the load-bearing ones, and the
second review pass was right to point out that an earlier version of this page claimed
they had all been replaced. The assertions that matter now walk rendered resource
attributes: the audit framework's `input_parameter` values, the rendered policy statements,
the alarm settings.

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

## Verified, and what remains genuinely open

Several findings were flagged `VERIFY` rather than asserted, which was the right call.
Checked against the provider schema:

- `aws_backup_global_settings` has no `region` attribute — confirmed absent, and handled
  above.
- `aws_backup_restore_testing_plan` and `aws_backup_restore_testing_selection` exist in
  v6 with the arguments used.

Both of those are statements about the **provider schema**, not about the AWS API. That
distinction matters and an earlier version of this page blurred it: `aws_backup_framework`
declares `control.name` as a plain required string with no validator, so "the provider
accepts these control names" is true of *any* string and proves nothing about whether AWS
does. `terraform validate` passing is not semantic correctness.

Open, and only settleable against a live account:

| Question | Mitigation taken |
| --- | --- |
| Whether AWS Backup populates `kms:ViaService` on copy-time KMS calls, or authorises them through a grant | `StringLikeIfExists` with a wildcard Region, so the condition cannot fail closed either way. The real narrowing is `source_principal_arns`, which names the source role and does not depend on a context key |
| Whether AWS Backup populates `aws:SourceAccount` on `AssumeRole` | `StringEqualsIfExists` / `ArnLikeIfExists`, correct either way |
| Whether the account root is exempt from an explicit `Deny` in a Backup vault access policy | The lockout was fixed regardless; the Terraform-lifecycle half never depended on the answer |
| Whether the Audit Manager control names and their parameter requirements are accepted by the API | None available offline. First apply will say |
| Whether `ControlScope` accepts a tag scope on every control it is applied to | Scope is applied only to the `BACKUP_RESOURCES_PROTECTED_BY_*` family, which AWS documents as resource-scoped |

Flagging these as uncertain rather than asserting them was more useful than a confident
guess would have been, in both directions.

---

## Second pass

The revised module went back to the same reviewer with the same brief. **No blockers**,
and the three original blockers were confirmed fixed by inspection rather than taken on
trust. But six of the fixes had introduced new defects, four confirmed by tests the
reviewer wrote to break the module.

The most serious was a fix undoing another fix:

**One acknowledgement flag gated two unrelated guards.**
`acknowledge_unchecked_copy_destinations` waived both the undeclared-lock-window check and
the `kms_key_arn_external` requirement. Worse, the "unchecked" list counted *managed*
destinations whose lock was deliberately disabled — so an ordinary sandbox, one unlocked
copy Region, forced the flag on, and the flag then waived the cross-account KMS
requirement. The largest finding from pass one silently re-opened, with the module's own
"the gap is visible" output reporting nothing.

*Fixed:* the two are separate concerns and are now separately enforced. The KMS
requirement is not waivable at all. A lock the operator turned off is a stated intent, not
an unknown, and no longer consumes an acknowledgement — it is reported in
`unvalidated_retention_targets`, which now also covers the primary vault. The previous
version errored loudly when it could not check a copy hop and stayed silent when it could
not check the vault every job writes to first, which is the reverse of the risk order.

The rest:

| Found | Response |
| --- | --- |
| `kms:ViaService` used a plain, fail-closed `StringEquals` pinned to one Region — contradicting the `IfExists` rule stated in a comment 30 lines above, on the one path with the least observability | `StringLikeIfExists` with a wildcard Region, plus `source_principal_arns` to narrow by role rather than by context key. The two tests that had enshrined opposite conventions now agree |
| The SNS **topic** policy used plain `StringEquals` on `aws:SourceAccount` while the **key** policy protecting the same publish used `IfExists` | Both use `IfExists`. A test asserts they agree |
| A `DenyInsecureTransport` statement was dropped in the `jsonencode` conversion, and the SNS default owner grant was replaced without being restated | Both restored, both tested |
| `cold_storage_after` could be set in a copy override but never cleared, so a short warm operational copy became inexpressible — and the `complete` example's own cross-Region copy silently gained a cold transition its comment said it did not have | `disable_cold_storage` sentinel added; the example corrected |
| `rate()` schedules mapped to a 1-day gap, reproducing the exact false positive the frequency derivation was written to remove | `rate(N unit)` parsed |
| The frequency parameter used `max` across rules. The control passes if *any* rule meets it, so the least frequent tier made it satisfiable by the monthly rule alone — the daily tier could be deleted undetected | `min`. The opposite error from the hardcoded `"1"`, not its correction |
| `vault_force_destroy` was inert against the deny-delete policy it ships alongside — `AccessDenied` on destroy with nothing to say which setting caused it | Precondition rejecting the combination, naming both ways out |
| Fields applying to one kind of destination were silently ignored on the other | Refused with a message saying which field belongs where |
| Restore-testing selection names sanitised hyphens only, so a resource type containing spaces was rejected at apply | Full sanitisation |

On test quality, the reviewer found four audit tests that stopped at a local — swapping
two locals inside `audit.tf` would have left all four passing — and one assertion
comparing a list to a string, vacuously true for two of three statements. All now walk the
rendered resource. One run asserted the opposite of what its name said and has been
renamed.

Seven regression tests were added for the findings above. Test count 73 → 83.

### What the second pass did not change

**The cross-account copy is still never restore-tested.** It lives in an account this
module has no credentials for, so testing it means a restore testing plan in the backup
account's own deployment. Documented in the scenario notes and the runbook rather than
papered over — it is the copy you would reach for during a ransomware incident, so it is
the worst one to be restoring from for the first time.

**Narrowing a committed compliance lock still produces a raw API error.** The
acknowledgement precondition covers creation only. Detecting the narrowing case means
reading the live lock state, which a plan cannot do.

**The framework's scope remains wider than the plan's selection**, because pattern-matched
tags cannot be expressed in a `ControlScope`. Resources tagged `ToBackup=true` with no
owner will be reported unprotected. That finding is correct — those resources do need an
owner — so it is documented rather than suppressed.
