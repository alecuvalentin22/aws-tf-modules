# ADR-0002 - Resource selection uses `condition`, not `selection_tag`

Status: Accepted
**Context:** Scenario 4 - resource selection

## Context

The requirement: *all supported resources with `ToBackup=true` **and**
`Owner=<owner@...>`*.

`aws_backup_selection` offers two ways to express tag matching:

```hcl
# Option A - selection_tag
selection_tag {
  type  = "STRINGEQUALS"
  key   = "ToBackup"
  value = "true"
}
selection_tag {
  type  = "STRINGEQUALS"
  key   = "Owner"
  value = "owner@example.com"
}

# Option B - condition
condition {
  string_equals {
    key   = "aws:ResourceTag/ToBackup"
    value = "true"
  }
  string_equals {
    key   = "aws:ResourceTag/Owner"
    value = "owner@example.com"
  }
}
```

They are not equivalent.

## Decision

Use `condition`.

## Rationale

**AWS Backup evaluates multiple `selection_tag` blocks with OR. `condition` entries are
evaluated with AND.**

Written as option A, a resource tagged `ToBackup=true` with no `Owner` tag at all is
still selected. The ownership half of the requirement does nothing at all.

Three properties make this the most dangerous kind of bug:

1. **It is invisible in a `terraform plan` diff.** Both forms produce a selection that
   looks correct.
2. **It fails in the direction that does not break anything.** You back up *more* than
   intended. No job fails, no alarm fires, nothing is missing during a restore. The
   symptom is a larger bill and a control that does not do what the compliance document
   says it does.
3. **It is discovered during an audit**, not during an incident, which is the worst
   way to find out that a control has not been enforced for a year.

The `Owner` tag requirement is not decoration. It is what makes a backed-up resource
attributable during a restore: knowing who to call about a database under restoration
at 3am is the difference between a fast recovery and a slow one.

## Consequences

- Adding a required tag is a map entry in `selection_required_tags`, all AND-ed.
- Wildcard matching uses `string_like`, so `Owner = "*@example.com"` enforces that a
  corporate owner exists without pinning one mailbox. Exclusions use `string_not_like`.
- The module **refuses an empty `selection_required_tags`**: an unconditional selection
  with `resources = ["*"]` backs up every resource in the account, which is a budget
  incident rather than a backup policy.
- A test asserts both that the conditions render as expected **and that `selection_tag`
  is not used at all**, so the module cannot regress to option A unnoticed.
