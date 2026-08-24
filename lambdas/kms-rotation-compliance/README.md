# `kms-rotation-compliance`

Custom AWS Config rule for [scenario 1, question 3](../../docs/scenario-1-key-rotation.md#q3--monitoring-compliance-with-an-aws-managed-service):
*identify, at any time, the resources (RDS, DynamoDB, S3) that are not covered by a
rotated key.*

## Why not the AWS managed rule

`cmk-backing-key-rotation-enabled` cannot answer that question, for two independent
reasons:

1. Its own documentation states it **does not apply to keys with imported (EXTERNAL)
   key material**. Every key in this estate is BYOK, so the rule is structurally
   non-functional, and it reports COMPLIANT, which is worse than reporting nothing.
2. It evaluates `AWS::KMS::Key`. It answers *"is this key rotated?"*, not *"is this
   database protected by a rotated key?"*. The requirement is to name the
   **resources**, so an operator knows which instance to act on.

## What this does

Evaluates the resource types and walks **resource -> KMS key -> rotation history**:

```
Config records a change to an RDS instance / DynamoDB table / S3 bucket
        |
        +- read the KMS key reference out of the configuration item
        +- resolve it (DescribeKey), in the Security account if needed
        +- ListKeyRotations
        +- compare the most recent rotation against the policy window
        |
        v
COMPLIANT / NON_COMPLIANT, annotated with the key ARN and the actual age
```

Findings are annotated so they are actionable on sight:

```
NON_COMPLIANT  Encrypted by arn:aws:kms:eu-central-1:111111111111:key/abcd-1234
               (BYOK, rotation is a manual HSM ceremony), last rotated 412 days ago,
               which exceeds the 365-day policy.
```

## Details that matter

| Behaviour | Why |
| --- | --- |
| An AWS-managed key is a **distinct** finding from a stale CMK | Different remediation. Conflating them buries the stale-CMK findings |
| A key that has **never rotated** is compliant until its *creation* date falls outside the window | Otherwise every newly created key is flagged on day one |
| A key that cannot be read **raises** rather than passing | The cross-account read is the part most likely to be misconfigured. Failing open would report COMPLIANT for every account that cannot reach the Security account - the exact opposite of the requirement |
| Deleted resources return `NOT_APPLICABLE` | Otherwise the last finding persists in Config and the dashboard never returns to green |
| BYOK origin is called out in the annotation | Remediation is an HSM ceremony, not a checkbox |
| Annotations truncated to 256 characters | Config's limit |

## Cross-account access

The keys live in the Security account; the rule runs in the workload account. It needs
a read-only role there for `kms:DescribeKey` and `kms:ListKeyRotations`, passed as the
`kmsReadRoleArn` rule parameter or the `KMS_READ_ROLE_ARN` environment variable.

This is the part most often missed at design time: the rule works correctly in the
account that owns the keys and fails everywhere else.

## Parameters

| Parameter | Default | |
| --- | --- | --- |
| `maxKeyAgeDays` | `365` | Policy window |
| `kmsReadRoleArn` | - | Role in the Security account |

## Tests

```bash
python3 -m unittest discover -s lambdas/kms-rotation-compliance/tests \
                             -t lambdas/kms-rotation-compliance -v
```

28 tests, no boto3, no credentials, no network. The decision logic takes its AWS access
through injected callables, which is what makes every branch reachable from a plain
unittest run, including the cross-account failure path and both sides of the policy
boundary. A Config rule whose logic can only be exercised by deploying it is
one nobody changes with confidence.

## Deployment

Package with the Lambda runtime's bundled boto3, deploy as an
`AWS::Config::ConfigRule` with `Source.Owner = CUSTOM_LAMBDA`, scoped to the resource
types in `KEY_PATHS`, with both change-triggered and periodic evaluation. Ship it in a
**conformance pack** via StackSets so it lands org-wide, aggregate results into the
Security account, and route `NON_COMPLIANT` through EventBridge to Security Hub.
