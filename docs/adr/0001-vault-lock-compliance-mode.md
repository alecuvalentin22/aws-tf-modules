# ADR-0001 - Vault Lock: compliance mode, reached through governance mode

**Status:** Accepted
**Context:** Scenario 4 - WORM protection

## Context

The brief requires Vault Lock "to prevent malicious & accidental backup deletion".
AWS Backup Vault Lock has two modes:

| | Governance | Compliance |
| --- | --- | --- |
| Removable | Yes, by a principal with `backup:DeleteBackupVaultLockConfiguration` | **No.** Not by the account root, not by AWS Support |
| Retention can be shortened | Yes | No |
| Recovery point deletable early | Yes, with permission | No |
| `terraform destroy` on a non-empty vault | Succeeds | **Fails** |

## Decision

**Compliance mode is the target state on all vaults. Governance mode is the default in
code, and reaching compliance mode requires an explicit acknowledgement variable.**

## Rationale

### Why compliance mode is the only mode that meets the requirement

The threat the isolated backup account exists to defend against is an attacker holding
administrator credentials - ransomware operators routinely obtain them, and deleting
backups before encrypting production is standard practice.

Governance mode is removable by anyone with sufficient IAM permissions. Against an
attacker who **has** those permissions, it offers nothing. It protects against accident,
not against malice, and the requirement says "malicious & accidental".

Locking only the primary copy would not be WORM in any meaningful sense either: the
attacker deletes the unlocked copies and the guarantee is gone. All three vaults are
locked.

### Why the code defaults to governance anyway

Compliance mode is irreversible, and the failure modes are expensive:

- A mistaken `min_retention_days` becomes a financial commitment for its full duration.
  Setting 2555 by accident means seven years of storage that cannot be deleted.
- A `delete_after` outside the lock's window is rejected **at job time, nightly, in
  production**, and the window cannot be widened to fix it.
- The vault cannot be destroyed while it holds recovery points, so a test deployment
  becomes permanent.
- There is no support path. AWS documents this explicitly.

The cost of getting compliance mode wrong is unbounded; the cost of spending two weeks
in governance mode first is two weeks.

### The rollout order

1. Apply with `lock.mode = "governance"`.
2. Run a full cycle: backup succeeds, cross-Region copy lands, cross-account copy lands.
3. **Restore from each vault**, including the cross-account one. This is the step that
   validates the KMS key policies and the vault access policies actually permit
   recovery, and it is the step most likely to reveal a missing grant.
4. Confirm the retention windows are correct and that the plan-time check passes.
5. Set `confirm_irreversible_compliance_lock = true` and `lock.mode = "compliance"`.

Step 3 is the one that matters. A cross-account copy whose key policy is subtly wrong
still *arrives*; it just cannot be restored. In governance mode that is a fixable
mistake. In compliance mode it is a locked vault full of unusable recovery points.

## Consequences

**Accepted:**
- `terraform destroy` will fail against locked, non-empty vaults. This is the feature
  working, and it must be stated in onboarding rather than discovered.
- Retention becomes a commitment, not a setting.
- A separate decommissioning procedure is needed: wait out the retention, then destroy.

**Mitigated in the module:**
- The `confirm_irreversible_compliance_lock` guard makes the irreversible step
  deliberate. Its error message states what cannot be undone and names the rollout order.
- The plan-time retention-window check (ADR-0003) catches the most common way a
  compliance lock becomes a nightly production failure.
- `changeable_for_days` (minimum 3) provides a grace window after apply.

**Rejected alternatives:**
- *Governance mode everywhere* - does not meet the requirement against a credentialled
  attacker.
- *Compliance on the backup account only* - the attacker deletes the unlocked prod-account
  copies; the RTO of restoring everything cross-account is far worse than restoring
  locally.
- *Compliance by default in code* - one careless `terraform apply` in a sandbox creates a
  vault that cannot be removed and bills for its full retention.
