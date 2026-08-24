#!/usr/bin/env python3
"""Lint every IAM/KMS/SNS policy this module renders, using the real plan output.

The module builds its policies with `jsonencode` rather than
`aws_iam_policy_document`, which is what lets `terraform test` assert on them
(a mocked provider cannot compute a data source). The cost of that choice is
that nothing validates the *contents* the way the data source would: a typo'd
action name, a condition operator that does not exist, or a condition key that
is meaningless for the action it is attached to would all render as perfectly
valid JSON and fail only at apply time, or, worse, evaluate to something
other than intended.

This closes that gap. It renders the policies from an actual `terraform plan`
and runs them through `parliament`, which knows AWS's action and condition-key
catalogue.

A linter reporting "clean" carries no information unless it is known to be
capable of reporting something else. So before looking at the real policies, this script runs three
deliberately broken fixtures through the same code path and FAILS if any of
them comes back clean. A dependency change that defanged the linter
would otherwise turn this into a green check that verifies nothing.

parliament is built for identity policies. Two of its findings are correct
behaviour for a *resource* policy and are suppressed by name:

  RESOURCE_STAR  A KMS key policy is attached to the key, so `"Resource": "*"`
                 means "this key". There is nothing else it could mean.
  MALFORMED      ...specifically "Statement contains neither Resource nor
                 NotResource", which is how every sts:AssumeRole trust policy
                 is written.

Suppressing by name rather than by severity keeps everything else in scope.

Usage:
    pip install parliament
    python3 scripts/lint_policies.py            # lint
    python3 scripts/lint_policies.py --keep     # keep the rendered policies
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(REPO, "modules", "backup-policy")
FIXTURES = os.path.join(REPO, "scripts", "policy-fixtures")

# Findings that are correct behaviour for a resource policy. See the docstring.
SUPPRESSED = {
    "RESOURCE_STAR",
    "MALFORMED",
}

# The module reads its account, partition and Region from data sources, which
# need credentials. A throwaway copy substitutes literals so the plan runs
# offline. Every substitution is asserted: if the module changes shape, this
# script fails loudly instead of linting nothing.
SUBSTITUTIONS = {
    "locals.tf": [
        ('data "aws_caller_identity" "current" {}', ""),
        ('data "aws_partition" "current" {}', ""),
        ('data "aws_region" "current" {}', ""),
        ("data.aws_caller_identity.current.account_id", '"111111111111"'),
        ("data.aws_partition.current.partition", '"aws"'),
        ("data.aws_region.current.region", '"eu-central-1"'),
    ],
    os.path.join("modules", "backup-vault", "main.tf"): [
        ('data "aws_caller_identity" "current" {}', ""),
        ('data "aws_partition" "current" {}', ""),
        ('data "aws_region" "current" {}', ""),
        ("data.aws_caller_identity.current.account_id", '"111111111111"'),
        ("data.aws_partition.current.partition", '"aws"'),
        ("data.aws_region.current.region", '"eu-central-1"'),
    ],
}

HARNESS_TF = """
provider "aws" {
  region                      = "eu-central-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
"""

# Three scenarios, because a policy whose content is unknown at plan time does
# not appear in the plan at all and therefore cannot be linted.
#
#   module_keys    the module creates its own CMKs, so the KMS key policies are
#                  rendered, but the backup role's inline policy references
#                  those keys' ARNs, which are unknown until apply.
#   supplied_keys  the caller passes existing key ARNs, so the key ARNs are known
#                  at the cost of the module not creating the keys whose
#                  policies the first scenario covers.
#   no_copies      no copy destinations at all, so the role's inline policy has
#                  no module-created vault ARN in it and finally renders. The
#                  copy statement is absent here by construction; its shape is
#                  covered by the terraform tests instead.
#
# The union reaches every policy the module renders. The one residual gap is the
# CopyIntoDestinationVaults statement, whose Resource list is always module-created
# vault ARNs and therefore never known before apply.
SCENARIOS = {
    "module_keys": """
name = "platform-backup"

copy_destinations = {
  secondary_region = { region = "eu-west-1" }
  backup_account = {
    vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
    lock_min_retention_days = 7
    lock_max_retention_days = 3650
    kms_key_arn_external    = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
  }
}
""",
    "supplied_keys": """
name = "platform-backup"

primary_vault = {
  create_kms_key = false
  kms_key_arn    = "arn:aws:kms:eu-central-1:111111111111:key/11111111-1111-1111-1111-111111111111"
}

copy_destinations = {
  secondary_region = {
    region         = "eu-west-1"
    create_kms_key = false
    kms_key_arn    = "arn:aws:kms:eu-west-1:111111111111:key/22222222-2222-2222-2222-222222222222"
  }
  backup_account = {
    vault_arn               = "arn:aws:backup:eu-central-1:222222222222:backup-vault:platform-iso"
    lock_min_retention_days = 7
    lock_max_retention_days = 3650
    kms_key_arn_external    = "arn:aws:kms:eu-central-1:222222222222:key/33333333-3333-3333-3333-333333333333"
  }
}
""",
    "no_copies": """
name = "platform-backup"

primary_vault = {
  create_kms_key = false
  kms_key_arn    = "arn:aws:kms:eu-central-1:111111111111:key/11111111-1111-1111-1111-111111111111"
}

copy_destinations = {}

rules = [{
  name      = "daily"
  schedule  = "cron(0 2 * * ? *)"
  retention = { delete_after = 35 }
}]
""",
}

# Where each resource type keeps its policy document.
POLICY_ATTRS = {
    "aws_kms_key": "policy",
    "aws_backup_vault_policy": "policy",
    "aws_sns_topic_policy": "policy",
    "aws_iam_role_policy": "policy",
    "aws_iam_role": "assume_role_policy",
}


def run(cmd: list[str], cwd: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, CHECKPOINT_DISABLE="1", TF_IN_AUTOMATION="1")
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


def analyze(document: str) -> list:
    from parliament import analyze_policy_string

    return analyze_policy_string(document).findings


def report(findings: list) -> list[str]:
    """Return the findings that are not suppressed, formatted."""
    out = []
    for f in findings:
        if f.issue in SUPPRESSED:
            continue
        detail = f" {f.detail}" if f.detail else ""
        out.append(f"[{f.issue}]{detail}")
    return out


def self_test() -> None:
    """Refuse to run unless the linter still catches known-bad policies."""
    print("Self-test: confirming the linter still detects known-bad policies")
    if not os.path.isdir(FIXTURES):
        sys.exit(f"error: fixtures directory missing: {FIXTURES}")

    fixtures = sorted(f for f in os.listdir(FIXTURES) if f.endswith(".json"))
    if not fixtures:
        sys.exit("error: no negative-control fixtures found")

    for name in fixtures:
        path = os.path.join(FIXTURES, name)
        with open(path) as fh:
            problems = report(analyze(fh.read()))
        if not problems:
            sys.exit(
                f"error: negative control {name} came back CLEAN.\n"
                "       The linter is not detecting what this check relies on it "
                "detecting, so a clean result on the real policies would mean nothing."
            )
        print(f"  {name}: caught ({problems[0]})")
    print()


def render_policies(workdir: str, scenario: str, tfvars: str) -> dict[str, str]:
    """Copy the module, stub its data sources, plan it, and pull the policies out."""
    mod = os.path.join(workdir, scenario)
    # Skip local Terraform state and caches: .terraform may be a symlink to a
    # shared plugin directory, and copying a lock file pins the throwaway copy
    # to whatever the developer last used.
    shutil.copytree(
        MODULE,
        mod,
        ignore=shutil.ignore_patterns(
            ".terraform", ".terraform.lock.hcl", "*.tfstate", "*.tfstate.*", "tfplan"
        ),
    )

    for relpath, pairs in SUBSTITUTIONS.items():
        path = os.path.join(mod, relpath)
        with open(path) as fh:
            body = fh.read()
        for old, new in pairs:
            if old not in body:
                sys.exit(
                    f"error: expected to find {old!r} in {relpath} and did not.\n"
                    "       The module changed shape; update SUBSTITUTIONS in this script "
                    "rather than letting it lint a stale or empty set."
                )
            body = body.replace(old, new)
        with open(path, "w") as fh:
            fh.write(body)

    with open(os.path.join(mod, "zz_harness.tf"), "w") as fh:
        fh.write(HARNESS_TF)
    with open(os.path.join(mod, "terraform.tfvars"), "w") as fh:
        fh.write(tfvars)

    # The module's own tests would run against the stubbed copy; drop them.
    shutil.rmtree(os.path.join(mod, "tests"), ignore_errors=True)

    for step in (["init", "-input=false", "-no-color"],
                 ["plan", "-input=false", "-no-color", "-out=tfplan"]):
        result = run(["terraform", *step], cwd=mod)
        if result.returncode != 0:
            sys.exit(f"error: terraform {step[0]} failed:\n{result.stdout}\n{result.stderr}")

    shown = run(["terraform", "show", "-json", "tfplan"], cwd=mod)
    if shown.returncode != 0:
        sys.exit(f"error: terraform show failed:\n{shown.stderr}")

    plan = json.loads(shown.stdout)

    def walk(module):
        yield from module.get("resources", [])
        for child in module.get("child_modules", []):
            yield from walk(child)

    policies: dict[str, str] = {}
    for res in walk(plan["planned_values"]["root_module"]):
        attr = POLICY_ATTRS.get(res["type"])
        if not attr:
            continue
        body = (res.get("values") or {}).get(attr)
        if not body:
            continue
        index = res.get("index")
        label = f"{res['type']}.{res['name']}" + (f"[{index}]" if index is not None else "")
        policies[label] = body

    return policies


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", metavar="DIR", help="write the rendered policies to DIR")
    args = parser.parse_args()

    try:
        import parliament  # noqa: F401
    except ImportError:
        sys.exit("error: parliament is not installed. Run: pip install parliament")

    self_test()

    print("Rendering policies from terraform plan")
    workdir = tempfile.mkdtemp(prefix="policy-lint-")
    policies: dict[str, str] = {}
    try:
        for scenario, tfvars in SCENARIOS.items():
            rendered = render_policies(workdir, scenario, tfvars)
            print(f"  scenario {scenario}: {len(rendered)} policies rendered")
            for label, body in rendered.items():
                # The scenarios overlap; keep one copy of each policy.
                policies.setdefault(label, body)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
    print()

    if not policies:
        sys.exit("error: no policies were rendered; the plan produced nothing to lint")

    if args.keep:
        os.makedirs(args.keep, exist_ok=True)

    print(f"Linting {len(policies)} rendered policy documents")
    failures = 0
    for label in sorted(policies):
        body = policies[label]

        try:
            json.loads(body)
        except json.JSONDecodeError as exc:
            print(f"  FAIL {label}: not valid JSON: {exc}")
            failures += 1
            continue

        if args.keep:
            safe = label.replace("/", "_").replace("[", "_").replace("]", "")
            with open(os.path.join(args.keep, f"{safe}.json"), "w") as fh:
                fh.write(body)

        problems = report(analyze(body))
        if problems:
            failures += 1
            print(f"  FAIL {label}")
            for problem in problems:
                print(f"       {problem}")
        else:
            print(f"  ok   {label}")

    print()
    if failures:
        print(f"{failures} of {len(policies)} policies have findings")
        return 1
    print(f"All {len(policies)} policies clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
