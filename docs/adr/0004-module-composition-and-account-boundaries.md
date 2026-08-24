# ADR-0004 - A leaf vault module, the provider `region` argument, and two states

Status: Accepted
**Context:** Scenario 4 - deploying at scale

## Context

The brief emphasises that "automation is key when deploying at scale". The topology is
three vaults across two Regions and two accounts, and a real estate will not stop at
three.

The blocking constraint: **Terraform cannot iterate over provider configurations.**
`for_each` cannot vary a provider alias. The conventional consequence is a module
hard-wired to a fixed set of locations, with the KMS key, the Vault Lock, the vault
policy and the notification wiring written out once per location, three near-identical
blocks that drift apart over time. Adding a Region means editing the module.

## Decision

Three parts:

1. **A `backup-vault` leaf module** owning one vault: its KMS key and key policy, its
   Vault Lock, its deny-delete access policy, its notifications.
2. **The AWS provider v6 per-resource `region` argument** to place vaults in any number
   of Regions **of the same account** from one provider configuration.
3. **An explicit account boundary**: cross-account destinations are *referenced*, not
   created, by the policy module.

## Rationale

### The `region` argument removes the constraint for the same-account case

AWS provider v6 accepts `region` on every resource and data source. So `for_each` over a
map of destinations works, and each instance lands in its own Region:

```hcl
copy_destinations = {
  ireland   = { region = "eu-west-1" }
  london    = { region = "eu-west-2" }
  stockholm = { region = "eu-north-1" }
}
```

Adding a Region is a map entry, not a provider alias plus a new copy of every resource.
A test runs the module with four managed Regions plus a cross-account target to prove
this is real rather than aspirational.

This requires provider `>= 6.0.0`, which is a deliberate floor rather than an accident.

### The leaf module stops the locations from drifting

A KMS key policy written three times will eventually differ in three ways. Written once
and instantiated three times, it cannot. The same applies to the lock, the deny-delete
policy and the notification wiring, all of which are security configuration.

### The account boundary is respected, not papered over

Cross-account genuinely needs different credentials, so it genuinely needs a provider
alias. Rather than force the policy module to take an alias it only sometimes needs, a
cross-account destination is an **external** destination: deploy `backup-vault` in the
backup account with `source_account_ids = [<prod>]`, and pass its ARN in.

In production these should be two states. A single Terraform state that can write to
both accounts is a single credential that can destroy both copies, precisely the
failure the isolated backup account exists to survive. Making the boundary a module
boundary makes the two-state split the natural way to deploy it, rather than a
refactoring exercise later.

The `complete` example wires both into one apply, because a runnable demonstration of
the whole topology is more useful than a correct one that cannot be run. It says so in a
comment and documents the intended split.

## Consequences

- **Provider `>= 6.0.0` is required.** Callers on v5 must upgrade.
- The two-module structure is slightly more to read than one flat module. The payoff is
  that the security-relevant configuration exists in exactly one place.
- `aws_backup_region_settings` and `aws_backup_global_settings` are account/Region and
  organisation **singletons**. A reusable module that manages them by default will fight
  another state for ownership, each apply reverting the other. Both are therefore opt-in
  and documented as belonging to the account baseline.
