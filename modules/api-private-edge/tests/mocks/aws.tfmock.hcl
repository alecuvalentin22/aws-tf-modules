# Shared provider mocks for `terraform test`.
#
# Two reasons these defaults exist rather than letting Terraform generate values:
#
#   1. The AWS provider validates several attributes client-side. A generated
#      random string for a KMS key ARN or an SNS topic ARN fails that validation
#      before any assertion runs.
#   2. Identity data sources feed interpolated ARNs throughout the module. Pinning
#      them keeps rendered policies readable when a test fails.

mock_data "aws_caller_identity" {
  defaults = {
    account_id = "111111111111"
    arn        = "arn:aws:iam::111111111111:role/terraform"
    id         = "111111111111"
    user_id    = "AIDAEXAMPLE"
  }
}

mock_data "aws_partition" {
  defaults = {
    partition          = "aws"
    id                 = "aws"
    dns_suffix         = "amazonaws.com"
    reverse_dns_prefix = "com.amazonaws"
  }
}

mock_data "aws_region" {
  defaults = {
    region      = "eu-central-1"
    name        = "eu-central-1"
    id          = "eu-central-1"
    description = "Europe (Frankfurt)"
  }
}

mock_data "aws_iam_policy_document" {
  defaults = {
    json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
  }
}

mock_resource "aws_kms_key" {
  defaults = {
    arn    = "arn:aws:kms:eu-central-1:111111111111:key/00000000-0000-0000-0000-000000000000"
    key_id = "00000000-0000-0000-0000-000000000000"
  }
}

mock_resource "aws_sns_topic" {
  defaults = {
    arn = "arn:aws:sns:eu-central-1:111111111111:mock-topic"
    id  = "arn:aws:sns:eu-central-1:111111111111:mock-topic"
  }
}

# The provider validates vault ARNs client-side (include_vaults accepts only a
# real ARN or "*"), so this has to be a well-formed value rather than a
# generated one. The consequence is that all mocked vaults share an ARN, so
# tests assert on the module's own lists rather than on set-typed attributes
# where identical values would collapse into one.
mock_resource "aws_backup_vault" {
  defaults = {
    arn = "arn:aws:backup:eu-central-1:111111111111:backup-vault:mock-vault"
  }
}

mock_resource "aws_backup_plan" {
  defaults = {
    arn     = "arn:aws:backup:eu-central-1:111111111111:backup-plan:00000000-0000-0000-0000-000000000000"
    id      = "00000000-0000-0000-0000-000000000000"
    version = "bW9jaw=="
  }
}

mock_resource "aws_iam_role" {
  defaults = {
    arn       = "arn:aws:iam::111111111111:role/mock-backup-role"
    unique_id = "AROAEXAMPLE"
  }
}

mock_resource "aws_backup_framework" {
  defaults = {
    arn = "arn:aws:backup:eu-central-1:111111111111:framework:mock-framework"
  }
}

mock_resource "aws_vpc_endpoint" {
  defaults = {
    id = "vpce-0123456789abcdef0"
  }
}

mock_data "aws_vpc_endpoint" {
  defaults = {
    id = "vpce-0123456789abcdef0"
    dns_entry = [{
      dns_name       = "vpce-0123456789abcdef0-abcd1234.execute-api.eu-central-1.vpce.amazonaws.com"
      hosted_zone_id = "Z1234567890ABC"
    }]
  }
}

mock_data "aws_secretsmanager_secret_version" {
  defaults = {
    secret_string = "mock-origin-secret"
  }
}

mock_resource "aws_api_gateway_rest_api" {
  defaults = {
    id            = "abcdef1234"
    arn           = "arn:aws:apigateway:eu-central-1::/restapis/abcdef1234"
    execution_arn = "arn:aws:execute-api:eu-central-1:111111111111:abcdef1234"
  }
}

mock_resource "aws_cloudfront_distribution" {
  defaults = {
    id             = "E1MOCKDIST"
    domain_name    = "d111111abcdef8.cloudfront.net"
    hosted_zone_id = "Z2FDTNDATAQYW2"
    arn            = "arn:aws:cloudfront::111111111111:distribution/E1MOCKDIST"
  }
}

mock_resource "aws_route53_zone" {
  defaults = {
    zone_id = "Z0987654321XYZ"
  }
}
