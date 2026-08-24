# ADR-0003 — Validate retention against Vault Lock windows at plan time

**Status:** Accepted
**Context:** Scenario 4 — the gap between apply-time and run-time failure

## Context

A Vault Lock enforces `min_retention_days` and `max_retention_days` **on every incoming
backup and copy job**. The enforcement happens when the job runs, not when Terraform
applies.

So a plan whose `delete_after` falls outside a destination vault's window:

1. Applies cleanly. `terraform apply` reports success.
2. Runs at 02:00. The job is **rejected**.
3. Repeats every night, in production, with nobody watching the apply output that
   introduced it.

Worse, on a compliance-mode lock the window **cannot be widened** afterwards. The only
remedies are changing the plan's retention or creating a new vault.

This is the highest-severity failure mode in the module, because it is silent, it is
delayed, and one of its fixes is unavailable.

## Decision

**Compute every `(rule, destination, delete_after)` triple against the Vault Lock window
of that specific destination, and fail at `terraform plan` with a message naming the
rule and the destination.**

```
rule "monthly" -> destination backup_account: delete_after=2555 is outside
the vault lock window [7, 365]
```

## Rationale

**Per destination, not one global window.** A single global check misses the case that
matters most: the local backup is inside the primary vault's window and succeeds, while
only the cross-account copy is rejected. That version is far harder to spot, because the
dashboard shows successful backup jobs and the failure is in a copy job to another
account.

**Fail at plan, not at apply.** A precondition on `aws_backup_plan` surfaces the error
in the plan output, so it is caught in a pull request rather than after a merge.

**External destinations are checked when declared, and refused when not.** The module
cannot read a Vault Lock in another account, so the caller supplies
`lock_min_retention_days` / `lock_max_retention_days`. Omitting both is a plan-time
**error** unless `acknowledge_unchecked_copy_destinations` is set, and the
`unvalidated_retention_targets` output names the omission either way.

An earlier version skipped the check silently. That was wrong in a specific way worth
recording: it made the module's headline guarantee inoperative on precisely the hop with
the least visibility and the strictest lock, with no signal anywhere. Failing open is
sometimes the right default; failing open *silently*, on a guardrail whose entire value
is catching this class of error, is not.

Guessing a window instead would be worse still — it would either block valid
configurations or give false assurance.

**A lock deliberately turned off is not the same thing.** `lock.enabled = false` on a
vault this module can see is a stated intent, not an unknown, so it does not require an
acknowledgement. It is still reported in `unvalidated_retention_targets`, and that
reporting covers the primary vault as well as the copy destinations — the vault every
backup job writes to first should not be the one omission nobody sees.

## Related checks in the same place

Other AWS constraints that also fail only at run time, moved to plan time:

| Constraint | Why it matters |
| --- | --- |
| `delete_after >= cold_storage_after + 90` | The archive tier has a 90-day minimum charge; earlier deletion costs more, and AWS rejects the lifecycle |
| Continuous backup requires `delete_after <= 35` and no cold storage | PITR is capped at 35 days and cannot be tiered |
| Archive opt-in requires `cold_storage_after` | Otherwise silently does nothing |
| `copy_to` names a defined destination | A typo would otherwise produce a plan with a missing copy |
| `copy_retention` key appears in `copy_to` | An override for a destination not copied to is silently ignored |

## Consequences

- Some configurations that AWS would accept at apply time are rejected at plan time.
  That is the intent: they are configurations AWS would then reject nightly.
- The checks live in `locals.tf` and `plan.tf` preconditions and must be kept in step
  with AWS's own constraints if those change.
- Every one of them has a test that supplies the bad configuration and asserts the
  refusal. A guardrail with no test proving it fires is decoration.
