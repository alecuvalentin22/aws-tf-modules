# Configs CloudFront and API Gateway accept and then misbehave on: a 403 on
# every request, a route that never receives traffic, or one caller getting
# another caller's response. None of them fails at apply time.
#
# Mocked provider, so no AWS account needed.

mock_provider "aws" {
  source = "./tests/mocks"
}

variables {
  name     = "orders-api"
  hostname = "api.example.com"
  vpc_id   = "vpc-0123456789abcdef0"

  vpc_endpoint_subnet_ids         = ["subnet-aaa", "subnet-bbb"]
  vpc_endpoint_security_group_ids = ["sg-0123456789abcdef0"]

  # REGIONAL, in the API's own Region. certificate_arn below is the us-east-1 one
  # CloudFront reads. The same hostname needs both.
  private_certificate_arn = "arn:aws:acm:eu-central-1:111111111111:certificate/private"

  # The dual-exposure runs front an internal ALB, which does not resolve on the
  # public internet and so has to be reached as a VPC origin.
  cloudfront_vpc_origin_ids = {
    "internal-alb.eu-central-1.elb.amazonaws.com" = "vo-0123456789abcdef0"
  }
}

# --------------------------------------------------------------------------
# A DNS record is not enough to reach a private API
# --------------------------------------------------------------------------

run "the_hostname_is_registered_as_a_private_custom_domain_name" {
  command = apply

  # Resolving api.example.com to the interface endpoint delivers the request and
  # leaves API Gateway with no way to tell which private API it is for: a private
  # API is addressed by its execute-api name or by an x-apigw-api-id header, and a
  # consumer calling the friendly hostname sends neither. The result is a 403 on
  # every call, from a name that resolves perfectly.
  assert {
    condition = alltrue([
      for c in aws_api_gateway_domain_name.private[0].endpoint_configuration :
      contains(c.types, "PRIVATE")
    ])
    error_message = "The custom domain name must itself be PRIVATE; a REGIONAL one is publicly resolvable and reintroduces the bypass."
  }

  assert {
    condition     = aws_api_gateway_domain_name_access_association.private[0].access_association_source == aws_vpc_endpoint.execute_api[0].id
    error_message = "Without an access association naming the endpoint, the domain name resolves and every call returns 403."
  }

  assert {
    condition = anytrue([
      for s in jsondecode(aws_api_gateway_domain_name.private[0].policy).Statement :
      try(s.Condition.StringEquals["aws:SourceVpce"], null) == aws_vpc_endpoint.execute_api[0].id
    ])
    error_message = "The domain name policy is evaluated before the API's, so it needs the endpoint condition too."
  }
}

run "refuses_a_record_that_would_resolve_and_then_403" {
  command = plan

  variables {
    create_private_domain_name = false
    # private_domain_name_id deliberately omitted.
  }

  # A name that resolves and then fails is harder to diagnose than one that does
  # not resolve, so the module refuses to publish the record on its own.
  expect_failures = [aws_route53_record.private[0]]
}

run "the_domain_name_can_be_owned_by_another_stack" {
  command = apply

  variables {
    create_private_domain_name = false
    private_domain_name_id     = "abcd1234"
  }

  assert {
    condition     = length(aws_api_gateway_domain_name.private) == 0
    error_message = "The module should not create a domain name it was told already exists."
  }

  assert {
    condition     = length(aws_route53_record.private) == 1
    error_message = "The record should still be published against the existing domain name."
  }
}

run "the_stage_mapping_is_created_only_once_a_stage_is_named" {
  command = apply

  variables {
    api_stage_name = "v1"
  }

  # The methods, the deployment and the stage belong to whoever defines what the
  # API does. This module owns only how it is exposed.
  assert {
    condition     = aws_api_gateway_base_path_mapping.private[0].stage_name == "v1"
    error_message = "A named stage should be mapped onto the domain name."
  }
}

run "no_stage_named_leaves_the_domain_name_unmapped" {
  command = apply

  assert {
    condition     = length(aws_api_gateway_base_path_mapping.private) == 0
    error_message = "Mapping a stage that does not exist yet fails the apply; unmapped is the correct interim state."
  }
}

run "the_private_zone_is_the_hostname_not_its_parent" {
  command = apply

  # Creating example.com privately to answer for api.example.com makes Route 53
  # Resolver serve EVERY *.example.com query in the VPC from this zone, returning
  # NXDOMAIN for every name it does not contain. It also means the second API to
  # use this module in the same VPC fails with ConflictingDomainExists.
  assert {
    condition     = aws_route53_zone.private[0].name == "api.example.com"
    error_message = "The private zone must be the hostname itself; a zone for the parent domain overrides resolution for everything beneath it inside the VPC."
  }
}

run "refuses_to_create_a_private_zone_for_an_apex" {
  command = plan

  variables {
    hostname = "example.com"
  }

  # An apex zone answers for every name beneath it inside the VPC, whichever way
  # it is derived.
  expect_failures = [aws_route53_zone.private[0]]
}

# --------------------------------------------------------------------------
# Private DNS on the endpoint is a VPC-wide decision
# --------------------------------------------------------------------------

run "private_dns_is_off_by_default_on_the_endpoint" {
  command = apply

  # Private DNS on an execute-api endpoint takes over *.execute-api.<region>.
  # amazonaws.com for the WHOLE VPC, so every caller resolves every API Gateway
  # hostname to this endpoint, including APIs still served regionally by other
  # teams. Those calls start returning 403, which breaks the phased migration this
  # design depends on.
  assert {
    condition     = aws_vpc_endpoint.execute_api[0].private_dns_enabled == false
    error_message = "Private DNS hijacks execute-api resolution for the entire VPC; the private custom domain name is what makes it unnecessary."
  }
}

run "private_dns_can_be_turned_on_deliberately" {
  command = apply

  variables {
    enable_endpoint_private_dns = true
  }

  assert {
    condition     = aws_vpc_endpoint.execute_api[0].private_dns_enabled == true
    error_message = "The setting should remain available for a VPC where taking over execute-api resolution is intended."
  }
}

run "the_domain_name_policy_denies_every_other_endpoint" {
  command = apply

  # An Allow on its own is not a control, by the same argument the module makes
  # for the API's own policy one layer down: a caller arriving through another
  # associated endpoint with an identity-based execute-api:Invoke grant is not
  # denied by an allow it simply does not match.
  assert {
    condition = anytrue([
      for s in jsondecode(aws_api_gateway_domain_name.private[0].policy).Statement :
      s.Effect == "Deny" &&
      try(s.Condition.StringNotEquals["aws:SourceVpce"], null) == aws_vpc_endpoint.execute_api[0].id
    ])
    error_message = "The domain name policy needs an explicit Deny, not only an Allow."
  }
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

run "the_viewer_host_header_reaches_the_private_custom_domain_name" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"
  }

  # The literal AllViewer UUID, not the module's own local. Comparing a rendered
  # attribute against the local that produced it is x == x: it passes whatever the
  # local is changed to, so it cannot detect the mistake it is named after.
  #
  # AllViewer is correct HERE because the origin is an ALB fronting a private custom
  # domain name, and API Gateway matches that domain against the Host it receives.
  # The familiar "strip Host" rule is about an execute-api origin, which this module
  # never has; applying it here 403s every external request.
  assert {
    condition = alltrue([
      for b in aws_cloudfront_distribution.this[0].default_cache_behavior :
      b.origin_request_policy_id == "216adef6-5c7f-47e4-b989-5492eafa07d3"
    ])
    error_message = "The default behavior must use the AllViewer managed policy (216adef6-5c7f-47e4-b989-5492eafa07d3). Stripping Host means the private API is asked for the ALB's name, which matches no registered domain name."
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
      b.cache_policy_id == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    ])
    error_message = "The default behavior must use the CachingDisabled managed policy (4135ea2d-6df8-44a3-9df3-4b5a84be39ad)."
  }

  assert {
    condition = alltrue([
      for b in aws_cloudfront_distribution.this[0].ordered_cache_behavior :
      b.cache_policy_id == "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    ])
    error_message = "Every ordered behavior must use the CachingDisabled managed policy; one that does not is a per-caller response served to the wrong caller."
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

run "an_internal_alb_origin_must_be_reached_as_a_vpc_origin" {
  command = plan

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"

    # Overrides the shared fixture: no VPC origin for the internal ALB.
    cloudfront_vpc_origin_ids = {}
  }

  # An internal ALB does not resolve on the public internet. CloudFront accepts
  # the distribution and then fails to connect on every request, which reads as an
  # origin outage rather than a configuration mistake.
  expect_failures = [aws_api_gateway_rest_api.this]
}

run "a_vpc_origin_replaces_the_custom_origin_config" {
  command = apply

  variables {
    exposure                 = "dual"
    certificate_arn          = "arn:aws:acm:us-east-1:111111111111:certificate/abcd"
    cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
    origin_secret_arn        = "arn:aws:secretsmanager:eu-central-1:111111111111:secret:origin-abcd"
    public_hosted_zone_id    = "Z0PUBLIC"
  }

  # The two are mutually exclusive on one origin, so exactly one is emitted.
  assert {
    condition = alltrue([
      for o in aws_cloudfront_distribution.this[0].origin :
      length(o.vpc_origin_config) == 1 && length(o.custom_origin_config) == 0
    ])
    error_message = "An origin listed in cloudfront_vpc_origin_ids must use vpc_origin_config and nothing else."
  }
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
