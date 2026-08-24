"""Unit tests for the KMS rotation compliance rule.

No boto3, no credentials, no network: the decision logic takes its AWS access through
injected callables, so every branch is reachable from a plain unittest run. That is the
point of the module split -- a Config rule whose logic can only be exercised by
deploying it is a Config rule nobody changes with confidence.

    python3 -m unittest discover -s lambdas/kms-rotation-compliance/tests -v
"""

import datetime as dt
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rotation_compliance import (  # noqa: E402
    COMPLIANT,
    NON_COMPLIANT,
    KeyLookupError,
    days_since,
    evaluate_resource,
    extract_key_reference,
    is_aws_managed_key,
    latest_rotation_date,
)

NOW = dt.datetime(2026, 8, 24, tzinfo=dt.timezone.utc)
CMK_ARN = "arn:aws:kms:eu-central-1:111111111111:key/abcd-1234"


def _describe(origin="EXTERNAL", manager="CUSTOMER", created=None, arn=CMK_ARN):
    def _fn(_key_reference):
        return {
            "Arn": arn,
            "Origin": origin,
            "KeyManager": manager,
            "CreationDate": created or dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        }

    return _fn


def _rotations(*dates):
    def _fn(_key_arn):
        return [{"RotationDate": d, "RotationType": "ON_DEMAND"} for d in dates]

    return _fn


class ExtractKeyReference(unittest.TestCase):
    """Each resource type stores its key in a different place in the Config item.

    A wrong path yields "not encrypted" rather than an error, so every supported type
    needs a test or the rule silently reports the wrong thing for that type.
    """

    def test_rds_instance(self):
        self.assertEqual(
            extract_key_reference("AWS::RDS::DBInstance", {"kmsKeyId": CMK_ARN}),
            CMK_ARN,
        )

    def test_dynamodb_table(self):
        config = {"sSEDescription": {"kMSMasterKeyArn": CMK_ARN}}
        self.assertEqual(extract_key_reference("AWS::DynamoDB::Table", config), CMK_ARN)

    def test_s3_bucket(self):
        config = {
            "serverSideEncryptionConfiguration": {
                "rules": [
                    {"applyServerSideEncryptionByDefault": {"kMSMasterKeyID": CMK_ARN}}
                ]
            }
        }
        self.assertEqual(extract_key_reference("AWS::S3::Bucket", config), CMK_ARN)

    def test_unencrypted_bucket_omits_the_block_entirely(self):
        self.assertIsNone(extract_key_reference("AWS::S3::Bucket", {}))

    def test_partial_path_does_not_raise(self):
        # An SSE config with an empty rules list is valid and must not blow up.
        config = {"serverSideEncryptionConfiguration": {"rules": []}}
        self.assertIsNone(extract_key_reference("AWS::S3::Bucket", config))

    def test_unsupported_resource_type(self):
        self.assertIsNone(extract_key_reference("AWS::EC2::Instance", {"kmsKeyId": CMK_ARN}))

    def test_empty_string_is_treated_as_absent(self):
        self.assertIsNone(extract_key_reference("AWS::RDS::DBInstance", {"kmsKeyId": ""}))


class AwsManagedKeyDetection(unittest.TestCase):
    def test_alias_form(self):
        self.assertTrue(is_aws_managed_key("alias/aws/s3"))

    def test_metadata_form(self):
        self.assertTrue(is_aws_managed_key(CMK_ARN, {"KeyManager": "AWS"}))

    def test_customer_managed_key(self):
        self.assertFalse(is_aws_managed_key(CMK_ARN, {"KeyManager": "CUSTOMER"}))

    def test_customer_alias_is_not_aws_managed(self):
        self.assertFalse(is_aws_managed_key("alias/prod-rds"))


class LatestRotationDate(unittest.TestCase):
    def test_picks_the_most_recent_rotation(self):
        d1 = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
        d2 = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        rotations = [{"RotationDate": d1}, {"RotationDate": d2}]
        self.assertEqual(latest_rotation_date({}, rotations), d2)

    def test_falls_back_to_creation_when_never_rotated(self):
        created = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
        self.assertEqual(latest_rotation_date({"CreationDate": created}, []), created)


class DaysSince(unittest.TestCase):
    def test_naive_datetime_is_treated_as_utc(self):
        self.assertEqual(days_since(dt.datetime(2026, 8, 14), NOW), 10)

    def test_future_timestamp_floors_at_zero(self):
        future = dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)
        self.assertEqual(days_since(future, NOW), 0)


class EvaluateResource(unittest.TestCase):
    def _evaluate(self, **kwargs):
        params = dict(
            resource_type="AWS::RDS::DBInstance",
            resource_id="db-1",
            configuration={"kmsKeyId": CMK_ARN},
            describe_key=_describe(),
            list_key_rotations=_rotations(dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)),
            now=NOW,
            max_age_days=365,
        )
        params.update(kwargs)
        return evaluate_resource(**params)

    def test_recently_rotated_key_is_compliant(self):
        compliance, annotation = self._evaluate()
        self.assertEqual(compliance, COMPLIANT)
        # The annotation has to name the key and the age, or the finding is the start
        # of an investigation rather than an action.
        self.assertIn(CMK_ARN, annotation)
        self.assertIn("84 days ago", annotation)

    def test_byok_origin_is_called_out_in_the_annotation(self):
        # Whoever picks up the finding needs to know remediation is an HSM ceremony,
        # not a checkbox.
        _, annotation = self._evaluate()
        self.assertIn("BYOK", annotation)

    def test_aws_kms_origin_omits_the_byok_note(self):
        _, annotation = self._evaluate(describe_key=_describe(origin="AWS_KMS"))
        self.assertNotIn("BYOK", annotation)

    def test_overdue_key_is_non_compliant(self):
        compliance, annotation = self._evaluate(
            list_key_rotations=_rotations(dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc))
        )
        self.assertEqual(compliance, NON_COMPLIANT)
        self.assertIn("exceeds the 365-day policy", annotation)

    def test_boundary_exactly_at_the_policy_limit_is_compliant(self):
        exactly = NOW - dt.timedelta(days=365)
        compliance, _ = self._evaluate(list_key_rotations=_rotations(exactly))
        self.assertEqual(compliance, COMPLIANT)

    def test_boundary_one_day_past_the_limit_is_non_compliant(self):
        just_over = NOW - dt.timedelta(days=366)
        compliance, _ = self._evaluate(list_key_rotations=_rotations(just_over))
        self.assertEqual(compliance, NON_COMPLIANT)

    def test_never_rotated_but_recently_created_is_compliant(self):
        # A key created last week has not rotated and does not need to have.
        recent = NOW - dt.timedelta(days=7)
        compliance, annotation = self._evaluate(
            describe_key=_describe(created=recent),
            list_key_rotations=_rotations(),
        )
        self.assertEqual(compliance, COMPLIANT)
        self.assertIn("created 7 days ago", annotation)

    def test_never_rotated_and_old_is_non_compliant(self):
        compliance, annotation = self._evaluate(
            describe_key=_describe(created=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)),
            list_key_rotations=_rotations(),
        )
        self.assertEqual(compliance, NON_COMPLIANT)
        self.assertIn("created", annotation)

    def test_unencrypted_resource_is_non_compliant(self):
        compliance, annotation = self._evaluate(configuration={})
        self.assertEqual(compliance, NON_COMPLIANT)
        self.assertIn("not encrypted", annotation)

    def test_aws_managed_key_is_a_distinct_finding(self):
        # Distinct from "stale CMK": the remediation is different, and conflating the
        # two buries the stale-CMK findings under a pile of these.
        compliance, annotation = self._evaluate(
            configuration={"kmsKeyId": "alias/aws/rds"}
        )
        self.assertEqual(compliance, NON_COMPLIANT)
        self.assertIn("AWS-managed key", annotation)

    def test_aws_managed_detected_from_metadata_after_lookup(self):
        compliance, annotation = self._evaluate(describe_key=_describe(manager="AWS"))
        self.assertEqual(compliance, NON_COMPLIANT)
        self.assertIn("AWS-managed", annotation)

    def test_key_that_cannot_be_read_raises_rather_than_passing(self):
        # The cross-account read is the part most likely to be misconfigured. Failing
        # open here would report COMPLIANT for every resource in every account that
        # cannot reach the Security account -- the exact opposite of the requirement.
        def _boom(_key_reference):
            raise RuntimeError("AccessDenied")

        with self.assertRaises(KeyLookupError):
            self._evaluate(describe_key=_boom)

    def test_annotation_stays_within_the_config_limit(self):
        long_arn = "arn:aws:kms:eu-central-1:111111111111:key/" + "a" * 300
        _, annotation = self._evaluate(
            configuration={"kmsKeyId": long_arn},
            describe_key=_describe(arn=long_arn),
        )
        # The handler truncates to 256; this asserts the raw annotation is not so long
        # that truncation would remove the compliance reason itself.
        self.assertLess(len(annotation) - len(long_arn), 200)


if __name__ == "__main__":
    unittest.main()
