"""Custom AWS Config rule: is this resource protected by a recently rotated KMS key?

Why this exists
---------------
The AWS managed rule `cmk-backing-key-rotation-enabled` cannot answer the question the
scenario actually asks, for two independent reasons:

1. Its own documentation states it does not apply to keys with imported (EXTERNAL) key
   material. Every key in this estate is BYOK, so the rule is structurally
   non-functional here -- and it reports COMPLIANT, which is worse than reporting
   nothing.
2. It evaluates `AWS::KMS::Key`. It answers "is this key rotated?", not "is this
   database protected by a rotated key?". The requirement is to identify the
   *resources* that are non-compliant, so an operator knows which RDS instance to act
   on rather than which key ARN to go and correlate by hand.

This rule evaluates the resource types instead, and walks resource -> KMS key ->
rotation history. The annotation names the key and the actual age, so a finding is
directly actionable rather than the start of an investigation.

Deployment: a custom AWS Config rule (change-triggered plus periodic), packaged in a
conformance pack and deployed org-wide via StackSets, with results aggregated in the
Security account and routed to Security Hub.

The module boundary is deliberate: everything below `evaluate_resource` is pure and
takes its AWS access through injected callables, so the decision logic is unit-testable
without boto3, without credentials and without network access.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import os
from typing import Any, Callable, Iterable, Optional

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"

DEFAULT_MAX_KEY_AGE_DAYS = 365

# Where the KMS key ARN lives in each resource type's Config configuration item.
# Config renders these from the service APIs, so the paths differ per service; getting
# one wrong yields NOT_APPLICABLE rather than an error, which is why each is covered by
# a test.
KEY_PATHS: dict[str, tuple[str, ...]] = {
    "AWS::RDS::DBInstance": ("kmsKeyId",),
    "AWS::RDS::DBCluster": ("kmsKeyId",),
    "AWS::DynamoDB::Table": ("sSEDescription", "kMSMasterKeyArn"),
    "AWS::S3::Bucket": (
        "serverSideEncryptionConfiguration",
        "rules",
        "0",
        "applyServerSideEncryptionByDefault",
        "kMSMasterKeyID",
    ),
    "AWS::EFS::FileSystem": ("kmsKeyId",),
}


class KeyLookupError(RuntimeError):
    """The key could not be inspected -- distinct from the key being non-compliant."""


def _dig(document: Any, path: Iterable[str]) -> Optional[Any]:
    """Walk a dotted path through nested dicts and lists, returning None on any miss.

    Config configuration items are inconsistently shaped between resource types and
    between the same type at different times (an unencrypted bucket simply omits the
    encryption block). Returning None rather than raising keeps "no key configured" a
    normal outcome instead of an error.
    """
    node = document
    for part in path:
        if node is None:
            return None
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(node, dict):
            node = node.get(part)
        else:
            return None
    return node


def extract_key_reference(resource_type: str, configuration: dict) -> Optional[str]:
    """Return the KMS key ARN, key id or alias a resource is encrypted with."""
    path = KEY_PATHS.get(resource_type)
    if path is None:
        return None
    value = _dig(configuration, path)
    return value if isinstance(value, str) and value else None


def is_aws_managed_key(key_reference: str, key_metadata: Optional[dict] = None) -> bool:
    """AWS-managed keys (alias/aws/*) cannot be rotated on our schedule.

    Treated as a distinct finding rather than folded into NON_COMPLIANT: "this bucket
    uses the AWS-managed key instead of a CMK" and "this bucket uses a CMK that is
    overdue for rotation" need different remediation, and conflating them buries the
    second in a pile of the first.
    """
    if key_reference.startswith("alias/aws/"):
        return True
    if key_metadata and key_metadata.get("KeyManager") == "AWS":
        return True
    return False


def days_since(timestamp: _dt.datetime, now: _dt.datetime) -> int:
    """Whole days between two aware datetimes, floored at zero."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=_dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    return max(0, (now - timestamp).days)


def latest_rotation_date(
    key_metadata: dict,
    rotations: list[dict],
) -> Optional[_dt.datetime]:
    """Most recent rotation, falling back to key creation if it has never rotated.

    A key that has never been rotated is not an error: it is compliant until its
    creation date falls outside the policy window. Treating "no rotations" as an
    immediate failure would flag every newly created key.
    """
    dates = [r["RotationDate"] for r in rotations if r.get("RotationDate")]
    if dates:
        return max(dates)
    return key_metadata.get("CreationDate")


def evaluate_resource(
    resource_type: str,
    resource_id: str,
    configuration: dict,
    describe_key: Callable[[str], dict],
    list_key_rotations: Callable[[str], list[dict]],
    now: _dt.datetime,
    max_age_days: int = DEFAULT_MAX_KEY_AGE_DAYS,
) -> tuple[str, str]:
    """Return (compliance_type, annotation) for one resource.

    Pure with respect to AWS: the two callables are the only access to KMS, which is
    what makes this testable without boto3 or credentials.
    """
    key_reference = extract_key_reference(resource_type, configuration)

    if key_reference is None:
        return (
            NON_COMPLIANT,
            "Resource is not encrypted with a KMS key, or no key could be determined "
            "from its configuration.",
        )

    if is_aws_managed_key(key_reference):
        return (
            NON_COMPLIANT,
            f"Encrypted with the AWS-managed key ({key_reference}) rather than a "
            "customer managed key, so rotation cannot be controlled or evidenced.",
        )

    try:
        metadata = describe_key(key_reference)
    except Exception as exc:  # noqa: BLE001 - surfaced as an annotation, see below
        # A cross-account read failure is a finding about our own configuration, not a
        # statement about the key. Reporting NON_COMPLIANT with the reason is correct:
        # a key we cannot inspect is a key we cannot evidence to a regulator.
        raise KeyLookupError(f"Could not describe key {key_reference}: {exc}") from exc

    if is_aws_managed_key(key_reference, metadata):
        return (
            NON_COMPLIANT,
            f"Key {metadata.get('Arn', key_reference)} is AWS-managed; rotation is not "
            "under our control.",
        )

    key_arn = metadata.get("Arn", key_reference)
    origin = metadata.get("Origin", "AWS_KMS")

    rotations = list_key_rotations(key_arn)
    last = latest_rotation_date(metadata, rotations)

    if last is None:
        return (
            NON_COMPLIANT,
            f"Key {key_arn} has no rotation history and no creation date; rotation "
            "cannot be evidenced.",
        )

    age = days_since(last, now)
    never_rotated = not rotations
    origin_note = " (BYOK, rotation is a manual HSM ceremony)" if origin == "EXTERNAL" else ""

    if age > max_age_days:
        detail = "created" if never_rotated else "last rotated"
        return (
            NON_COMPLIANT,
            f"Encrypted by {key_arn}{origin_note}, {detail} {age} days ago, which "
            f"exceeds the {max_age_days}-day policy.",
        )

    detail = "created" if never_rotated else "last rotated"
    return (
        COMPLIANT,
        f"Encrypted by {key_arn}{origin_note}, {detail} {age} days ago "
        f"(policy: {max_age_days} days).",
    )


# ---------------------------------------------------------------------------
# AWS Config plumbing. Everything above is pure; everything below is I/O.
# ---------------------------------------------------------------------------


def _kms_client(region: str, role_arn: Optional[str]):
    """KMS client, optionally in the Security account where the keys live.

    The keys are centralised in a Security account while this rule runs in the workload
    account, so a read-only cross-account role is required. This is the part most often
    missed at design time -- the rule works fine in the account that owns the keys and
    silently fails everywhere else.
    """
    import boto3  # imported here so the pure logic above stays importable without it

    if not role_arn:
        return boto3.client("kms", region_name=region)

    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="config-kms-rotation-compliance"
    )["Credentials"]
    return boto3.client(
        "kms",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _make_key_readers(client):
    def describe_key(key_reference: str) -> dict:
        return client.describe_key(KeyId=key_reference)["KeyMetadata"]

    def list_key_rotations(key_arn: str) -> list[dict]:
        rotations: list[dict] = []
        paginator_args: dict[str, Any] = {"KeyId": key_arn}
        while True:
            page = client.list_key_rotations(**paginator_args)
            rotations.extend(page.get("Rotations", []))
            if not page.get("Truncated"):
                break
            paginator_args["Marker"] = page["NextMarker"]
        return rotations

    return describe_key, list_key_rotations


def lambda_handler(event: dict, context) -> dict:  # noqa: ANN001 - AWS signature
    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event.get("ruleParameters") or "{}")

    max_age_days = int(rule_parameters.get("maxKeyAgeDays", DEFAULT_MAX_KEY_AGE_DAYS))
    kms_role_arn = rule_parameters.get("kmsReadRoleArn") or os.environ.get(
        "KMS_READ_ROLE_ARN"
    )

    item = invoking_event.get("configurationItem") or invoking_event.get(
        "configurationItemSummary"
    )
    if not item:
        LOG.info("No configuration item in event; nothing to evaluate.")
        return {"evaluations": 0}

    resource_type = item["resourceType"]
    resource_id = item["resourceId"]
    region = item.get("awsRegion") or os.environ["AWS_REGION"]

    # A deleted resource must be reported NOT_APPLICABLE, otherwise its last finding
    # stays in Config forever and the compliance dashboard never goes green again.
    status = item.get("configurationItemStatus")
    if status in ("ResourceDeleted", "ResourceDeletedNotRecorded"):
        compliance, annotation = NOT_APPLICABLE, "Resource has been deleted."
    elif resource_type not in KEY_PATHS:
        compliance, annotation = NOT_APPLICABLE, f"{resource_type} is not in scope."
    else:
        now = _dt.datetime.now(_dt.timezone.utc)
        client = _kms_client(region, kms_role_arn)
        describe_key, list_key_rotations = _make_key_readers(client)
        try:
            compliance, annotation = evaluate_resource(
                resource_type=resource_type,
                resource_id=resource_id,
                configuration=json.loads(item["configuration"])
                if isinstance(item.get("configuration"), str)
                else item.get("configuration", {}),
                describe_key=describe_key,
                list_key_rotations=list_key_rotations,
                now=now,
                max_age_days=max_age_days,
            )
        except KeyLookupError as exc:
            compliance, annotation = NON_COMPLIANT, str(exc)

    # Config truncates annotations at 256 characters.
    annotation = annotation[:256]
    LOG.info("%s %s -> %s: %s", resource_type, resource_id, compliance, annotation)

    import boto3

    boto3.client("config").put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": resource_type,
                "ComplianceResourceId": resource_id,
                "ComplianceType": compliance,
                "Annotation": annotation,
                "OrderingTimestamp": item["configurationItemCaptureTime"],
            }
        ],
        ResultToken=event["resultToken"],
    )
    return {"evaluations": 1, "compliance": compliance}
