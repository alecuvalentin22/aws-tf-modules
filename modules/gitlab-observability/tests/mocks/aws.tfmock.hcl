# Provider mocks for `terraform test`.
#
# The AWS provider validates several attributes client-side, so anything it
# parses as an ARN has to be well-formed here rather than left to Terraform's
# generated random strings, which fail before any assertion runs.

mock_resource "aws_sns_topic" {
  defaults = {
    arn = "arn:aws:sns:eu-central-1:111111111111:mock-topic"
    id  = "arn:aws:sns:eu-central-1:111111111111:mock-topic"
  }
}

mock_resource "aws_synthetics_canary" {
  defaults = {
    arn = "arn:aws:synthetics:eu-central-1:111111111111:canary:mock"
  }
}

mock_resource "aws_cloudwatch_metric_alarm" {
  defaults = {
    arn = "arn:aws:cloudwatch:eu-central-1:111111111111:alarm:mock"
  }
}
