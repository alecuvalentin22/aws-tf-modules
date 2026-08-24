# Provider mocks for `terraform test`.
#
# Two reasons these defaults exist rather than letting Terraform generate values:
#
#   1. The AWS provider validates several attributes client-side. A generated
#      random string fails that validation before any assertion runs, so anything
#      parsed as an ARN or an endpoint ID has to be well-formed here.
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

mock_resource "aws_vpc_endpoint" {
  defaults = {
    id = "vpce-0123456789abcdef0"
  }
}

# One entry only, and it is the Region-wide name. A real endpoint also publishes
# a zonal name per AZ, which is what the module's shortest-name selection exists
# to distinguish; the test for that reads the module's own logic rather than
# relying on mock ordering.
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

# The provider parses domain_name_arn client-side before the access association
# is planned, so a generated value fails before any assertion runs.
mock_resource "aws_api_gateway_domain_name" {
  defaults = {
    arn            = "arn:aws:apigateway:eu-central-1:111111111111:/domainnames/api.example.com+abcd1234"
    domain_name_id = "abcd1234"
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
