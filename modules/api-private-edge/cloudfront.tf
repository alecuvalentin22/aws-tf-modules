
locals {
  # Managed policy IDs. Referenced by their AWS-published values rather than by a
  # data source so the intent is legible in review and cannot resolve to
  # something else.
  #
  # CachingDisabled: API responses are per-caller and must never be shared.
  cache_policy_caching_disabled = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

  # AllViewer: forwards everything the viewer sent, Host included.
  origin_request_policy_all_viewer = "216adef6-5c7f-47e4-b989-5492eafa07d3"

  # AllViewerExceptHostHeader: everything EXCEPT Host.
  origin_request_policy_all_viewer_except_host = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

  # Which of the two is correct depends entirely on what the origin routes on, and
  # the usual advice points the wrong way for this topology.
  #
  # "Never forward Host to API Gateway" is about an execute-api origin: API Gateway
  # matches the Host against its own hostname, the viewer's value matches nothing,
  # and every request 403s. It is the most common cause of "CloudFront in front of
  # API Gateway returns 403".
  #
  # This module's origin is never execute-api. It is an ALB in front of a PRIVATE
  # API reached through a private custom domain name, and API Gateway matches that
  # domain against the SNI/Host name it receives. Stripping Host here means the API
  # is asked for internal-alb-....elb.amazonaws.com, which matches no registered
  # domain name and carries no x-apigw-api-id, so every external request 403s: the
  # identical symptom, caused by the opposite setting.
  #
  # The viewer's Host is already the hostname the domain name is registered under,
  # because it is the distribution's alias. So it is forwarded.
  origin_request_policy = local.origin_request_policy_all_viewer
}

# Guarded on the ARN being present as well as on the exposure mode. Reading the
# data source with a null secret_id fails first, with Terraform's generic
# "Missing required argument" pointing at this line, instead of the precondition
# in main.tf explaining why the secret is required at all.
data "aws_secretsmanager_secret_version" "origin" {
  count = local.create_distribution ? 1 : 0

  secret_id = var.origin_secret_arn
}

# CloudFront is global and a distribution can be managed from any Region, so
# this module needs no us-east-1 provider alias. What DOES have to be in
# us-east-1 is the ACM certificate and, if used, the CLOUDFRONT-scope WebACL --
# both of which are inputs here rather than resources, so that constraint
# belongs to the caller.
resource "aws_cloudfront_distribution" "this" {
  count = local.create_distribution ? 1 : 0

  enabled         = true
  comment         = "${var.name} public front door"
  aliases         = [var.hostname]
  is_ipv6_enabled = true
  web_acl_id      = var.web_acl_arn
  tags            = local.tags

  viewer_certificate {
    acm_certificate_arn      = var.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # One origin per distinct upstream, keyed by domain so several routes can share
  # one without declaring it twice.
  dynamic "origin" {
    for_each = toset(concat(
      [var.cloudfront_origin_domain],
      [for r in var.path_routes : r.origin_domain if r.origin_domain != null],
    ))

    content {
      origin_id   = origin.value
      domain_name = origin.value

      # A private origin is reached through a VPC origin, not over the internet.
      # The two are mutually exclusive on one origin, so exactly one of these
      # blocks is emitted per upstream.
      dynamic "vpc_origin_config" {
        for_each = contains(keys(var.cloudfront_vpc_origin_ids), origin.value) ? [1] : []

        content {
          vpc_origin_id = var.cloudfront_vpc_origin_ids[origin.value]
        }
      }

      dynamic "custom_origin_config" {
        for_each = contains(keys(var.cloudfront_vpc_origin_ids), origin.value) ? [] : [1]

        content {
          http_port              = 80
          https_port             = 443
          origin_protocol_policy = "https-only"
          origin_ssl_protocols   = ["TLSv1.2"]
        }
      }

      # Proves to the origin that the request arrived through this distribution.
      # The regional WAF denies by default and allows only requests carrying it.
      #
      # This holds for exactly as long as the secret does, and the secret is in
      # the Terraform state and in the distribution config, because CloudFront
      # takes a custom header only as a literal. That is why it is a transitional
      # control rather than the answer. The answer is that a private API has no
      # public endpoint to bypass to.
      custom_header {
        name  = var.origin_secret_header_name
        value = data.aws_secretsmanager_secret_version.origin[0].secret_string
      }
    }
  }

  default_cache_behavior {
    target_origin_id       = var.cloudfront_origin_domain
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = local.cache_policy_caching_disabled
    origin_request_policy_id = local.origin_request_policy
  }

  # Order is preserved from var.path_routes, and main.tf refuses an ordering
  # where a general pattern shadows a later specific one.
  dynamic "ordered_cache_behavior" {
    for_each = var.path_routes

    content {
      path_pattern           = ordered_cache_behavior.value.path_pattern
      target_origin_id       = coalesce(ordered_cache_behavior.value.origin_domain, var.cloudfront_origin_domain)
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ordered_cache_behavior.value.allowed_methods
      cached_methods         = ["GET", "HEAD"]

      cache_policy_id          = local.cache_policy_caching_disabled
      origin_request_policy_id = local.origin_request_policy
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}
