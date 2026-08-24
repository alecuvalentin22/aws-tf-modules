# The failure modes this module exists to prevent.
#
# Every one of these is a configuration AWS accepts and then behaves badly on:
# a 403 on every request, a route that silently never receives traffic, or one
# caller receiving another caller's response. None fails at apply time.
#
# Runs against a mocked provider, so no AWS account or credentials are needed.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name     = "orders-api"
  hostname = "api.example.com"
  vpc_id   = "vpc-0123456789abcdef0"

  vpc_endpoint_subnet_ids         = ["subnet-aaa", "subnet-bbb"]
  vpc_endpoint_security_group_ids = ["sg-0123456789abcdef0"]
}

# --------------------------------------------------------------------------
# The bypass
# --------------------------------------------------------------------------

run "the_api_is_private_so_there_is_no_public_endpoint_to_bypass" {
  command = apply

  # This is the whole point. A regional endpoint left resolvable on the internet
  # means every edge protection can be skipped with one curl, and the real
  # security posture becomes whatever the regional WAF enforces.
  assert {
    condition = alltrue([
      for c in aws_api_gateway_rest_api.this.endpoint_configuration :
      contains(c.types, "PRIVATE")
    ])
    error_message = "The API must be PRIVATE. A REGIONAL or EDGE endpoint stays publicly resolvable."
  }
}

run "the_resource_policy_denies_every_other_endpoint" {
  command = apply

  # PRIVATE removes the public route. It does NOT stop a different VPC endpoint
  # in the account from calling in, and an absent allow is not enough: an
  # identity policy elsewhere granting execute-api:Invoke would suffice. The
  # explicit deny is what closes it.
  assert {
    condition = anytrue([
      for s in jsondecode(local.api_policy).Statement :
      s.Effect == "Deny" &&
      try(s.Condition.StringNotEquals["aws:SourceVpce"], null) == "vpce-0123456789abcdef0"
    ])
    error_message = "The resource policy must explicitly deny calls arriving through any endpoint other than the permitted one."
  }
}

run "the_resource_policy_can_be_narrowed_to_named_principals" {
  command = apply

  variables {
    allowed_principal_arns = ["arn:aws:iam::111111111111:role/orders-service"]
  }

  # The endpoint condition is the network control; this is the identity control.
  # They are not substitutes.
  assert {
    condition = anytrue([
      for s in jsondecode(local.api_policy).Statement :
      s.Effect == "Allow" &&
      contains(try(s.Principal.AWS, []), "arn:aws:iam::111111111111:role/orders-service")
    ])
    error_message = "Named principals should replace the wildcard in the allow statement."
  }
}

run "no_principals_named_means_any_caller_through_the_endpoint" {
  command = apply

  assert {
    condition = anytrue([
      for s in jsondecode(local.api_policy).Statement :
      s.Effect == "Allow" && s.Principal == "*"
    ])
    error_message = "With no principals named the allow should be a wildcard, leaving the endpoint condition as the only control."
  }
}

# --------------------------------------------------------------------------
# Split-horizon DNS
# --------------------------------------------------------------------------

run "the_private_record_points_at_the_interface_endpoint" {
  command = apply

  # Same hostname, resolved differently depending on where the caller is. This
  # is what makes the migration cheap: an internal consumer changes nothing, and
  # the cutover is a DNS change that reverses in minutes.
  assert {
    condition     = aws_route53_record.private[0].name == "api.example.com"
    error_message = "The private record must carry the same hostname external callers use."
  }

  assert {
    condition     = length(aws_route53_record.public) == 0
    error_message = "An internal-only API should publish no public record."
  }
}

run "records_can_be_held_back_for_a_separate_cutover" {
  command = apply

  variables {
    create_dns_records = false
  }

  # Everything else can be created and verified while live traffic still follows
  # the old path.
  assert {
    condition     = length(aws_route53_record.private) == 0
    error_message = "create_dns_records = false should stage the infrastructure without moving traffic."
  }

  assert {
    condition     = aws_api_gateway_rest_api.this.id != null
    error_message = "The API should still be created when the DNS cutover is deferred."
  }
}

# --------------------------------------------------------------------------
# The four CloudFront traps
# --------------------------------------------------------------------------

run "the_viewer_host_header_is_not_forwarded_to_the_origin" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"
  }

  # API Gateway routes on Host. Forwarding the viewer's value to an execute-api
  # origin returns 403 on every request, and this is the single most common
  # cause of "CloudFront in front of API Gateway returns 403".
  assert {
    condition = alltrue([
      for b in aws_cloudfront_distribution.this[0].default_cache_behavior :
      b.origin_request_policy_id == local.origin_request_policy_all_viewer_except_host
    ])
    error_message = "Use the AllViewerExceptHostHeader managed policy; forwarding Host to execute-api returns 403 on every request."
  }
}

run "caching_is_disabled_on_every_behavior" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"

    path_routes = [
      { path_pattern = "/policies/*" },
      { path_pattern = "/claims/*" },
    ]
  }

  # API responses here are per-caller. The failure mode of caching them is one
  # customer receiving another customer's response, which surfaces as a data
  # breach rather than as a bug.
  assert {
    condition = alltrue([
      for b in aws_cloudfront_distribution.this[0].default_cache_behavior :
      b.cache_policy_id == local.cache_policy_caching_disabled
    ])
    error_message = "The default behavior must use CachingDisabled."
  }

  assert {
    condition = alltrue([
      for b in aws_cloudfront_distribution.this[0].ordered_cache_behavior :
      b.cache_policy_id == local.cache_policy_caching_disabled
    ])
    error_message = "Every ordered behavior must use CachingDisabled; one that does not is a per-caller response served to the wrong caller."
  }
}

run "a_general_pattern_may_not_shadow_a_later_specific_one" {
  command = plan

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"

    # /api/* matches everything /api/admin/* would, and it is listed first, so
    # the admin route never receives traffic. First-match-wins ordering makes
    # this a security setting rather than a cosmetic one, and nothing in a plan
    # diff or the console indicates it.
    path_routes = [
      { path_pattern = "/api/*" },
      { path_pattern = "/api/admin/*" },
    ]
  }

  expect_failures = [aws_api_gateway_rest_api.this]
}

run "specific_before_general_is_accepted" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"

    path_routes = [
      { path_pattern = "/api/admin/*" },
      { path_pattern = "/api/*" },
    ]
  }

  assert {
    condition     = length(local.shadowed_routes) == 0
    error_message = "Listing the specific pattern first is the correct ordering and must be accepted."
  }

  # The routing table as CloudFront will evaluate it, in order. Worth putting in
  # a change record: this ordering is the part most often misread from Terraform.
  assert {
    condition     = local.effective_routing_preview[0].path_pattern == "/api/admin/*"
    error_message = "The routing preview should reflect evaluation order."
  }
}

run "rejects_duplicate_path_patterns" {
  command = plan

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"

    path_routes = [
      { path_pattern = "/claims/*" },
      { path_pattern = "/claims/*" },
    ]
  }

  expect_failures = [var.path_routes]
}

# --------------------------------------------------------------------------
# The transitional mitigation
# --------------------------------------------------------------------------

run "the_origin_secret_must_come_from_secrets_manager" {
  command = plan

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    public_hosted_zone_id    = "Z0PUBLIC"
    # origin_secret_arn deliberately omitted.
  }

  # A literal would be written to the Terraform state and to the distribution
  # config, and this control is worth exactly as much as the secrecy of that
  # value.
  expect_failures = [aws_api_gateway_rest_api.this]
}

run "a_dual_exposure_api_still_has_no_public_execute_api_endpoint" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"
  }

  # Serving both audiences does not mean going back to a public endpoint. One
  # private API, two front doors.
  assert {
    condition = alltrue([
      for c in aws_api_gateway_rest_api.this.endpoint_configuration :
      contains(c.types, "PRIVATE")
    ])
    error_message = "A dual-exposure API must remain PRIVATE; the public path goes through CloudFront, not through execute-api."
  }

  assert {
    condition     = length(aws_route53_record.public) == 1
    error_message = "A dual-exposure API needs the public record pointing at CloudFront."
  }
}

# --------------------------------------------------------------------------
# Endpoint hygiene
# --------------------------------------------------------------------------

run "rejects_a_single_az_interface_endpoint" {
  command = plan

  variables {
    vpc_endpoint_subnet_ids = ["subnet-aaa"]
  }

  # The endpoint becomes a single-AZ dependency for every internal caller.
  expect_failures = [aws_vpc_endpoint.execute_api]
}

run "an_existing_endpoint_can_be_shared" {
  command = apply

  variables {
    vpc_endpoint_id = "vpce-99999999999999999"
  }

  # An interface endpoint is billed per hour per AZ, so one per API multiplies a
  # fixed cost by the number of teams for no benefit.
  assert {
    condition     = length(aws_vpc_endpoint.execute_api) == 0
    error_message = "Supplying an endpoint should not create another one."
  }

  assert {
    condition     = local.endpoint_id == "vpce-99999999999999999"
    error_message = "The supplied endpoint should be the one named in the resource policy."
  }
}
