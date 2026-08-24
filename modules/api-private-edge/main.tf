###############################################################################
# A private API Gateway reached through PrivateLink, with split-horizon DNS and
# an optional CloudFront front door for callers outside the network.
#
# The problem this addresses: a regional execute-api endpoint stays publicly
# resolvable even when CloudFront, Shield and a global WAF sit in front of it,
# so every edge protection can be skipped with one curl against the regional
# URL. The real security posture becomes whatever the regional WAF enforces.
#
# Making the API PRIVATE removes public invocability. The execute-api name still
# resolves and answers 403; what is gone is any way to reach the API through it.
# The bypass is not blocked by a rule someone could misconfigure, it has no path.
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  tags = merge(
    {
      ManagedBy = "terraform"
      Module    = "api-private-edge"
    },
    var.tags,
  )

  create_endpoint = var.vpc_endpoint_id == null
  endpoint_id     = local.create_endpoint ? aws_vpc_endpoint.execute_api[0].id : var.vpc_endpoint_id

  public_front_door = var.exposure == "dual"

  # The distribution is built only once everything it needs is present. Without
  # this, a missing input fails inside the resource with Terraform's generic
  # "argument is required" instead of the precondition below explaining WHY the
  # input is required. The plan still fails either way: the preconditions on the
  # API are what report it.
  create_distribution = (
    local.public_front_door &&
    var.certificate_arn != null &&
    var.origin_secret_arn != null &&
    var.cloudfront_origin_domain != null
  )

  create_private_zone = var.private_hosted_zone_id == null
  private_zone_id     = local.create_private_zone ? aws_route53_zone.private[0].zone_id : var.private_hosted_zone_id

  # The zone is the hostname itself, not its parent.
  #
  # Creating example.com privately in order to answer for api.example.com makes
  # Route 53 Resolver serve EVERY *.example.com query in that VPC out of this zone,
  # returning NXDOMAIN for every name it does not contain: other teams' APIs, mail,
  # SaaS CNAMEs. It also means the second API to use this module in the same VPC
  # fails with ConflictingDomainExists, because one VPC cannot associate two private
  # zones of the same name.
  #
  # A zone named for the full hostname holds one record at its own apex and
  # overrides nothing else.
  zone_name = var.hostname

  # ---------------------------------------------------------------------------
  # Behavior ordering.
  #
  # CloudFront evaluates ordered cache behaviors first-match-wins. A general
  # pattern placed above a specific one shadows it, and the result is a
  # route that never receives traffic, or worse, a permissive behavior applying
  # where a restrictive one was intended. Neither is visible in a plan diff.
  #
  # A pattern shadows a later one when the later one would also match everything
  # the earlier one matches. Comparing the literal prefix before any wildcard is
  # enough to catch the cases that occur in practice.
  # ---------------------------------------------------------------------------
  route_prefixes = [
    for r in var.path_routes : split("*", r.path_pattern)[0]
  ]

  effective_routing_preview = concat(
    [
      for i, r in var.path_routes : {
        position     = i + 1
        path_pattern = r.path_pattern
        origin       = coalesce(r.origin_domain, var.cloudfront_origin_domain, "")
      }
    ],
    var.exposure == "dual" ? [{
      position     = length(var.path_routes) + 1
      path_pattern = "* (default)"
      origin       = coalesce(var.cloudfront_origin_domain, "")
    }] : [],
  )

  # Every upstream the distribution will be given, primary plus per-route.
  origin_domains = local.public_front_door ? distinct(concat(
    [var.cloudfront_origin_domain],
    [for r in var.path_routes : r.origin_domain if r.origin_domain != null],
  )) : []

  # An internal ALB is not resolvable from the internet, so CloudFront cannot
  # reach it as an ordinary custom origin. The distribution is accepted and then
  # errors on every request, which looks like an origin outage rather than a
  # configuration mistake.
  unreachable_origins = [
    for d in local.origin_domains :
    format("%q is an internal load balancer and has no entry in cloudfront_vpc_origin_ids", d)
    if d != null && startswith(d, "internal-") && !contains(keys(var.cloudfront_vpc_origin_ids), d)
  ]

  shadowed_routes = flatten([
    for i, r in var.path_routes : [
      for j, later in var.path_routes :
      format(
        "%q at position %d is shadowed by %q at position %d",
        later.path_pattern, j + 1, r.path_pattern, i + 1,
      )
      if j > i &&
      strcontains(r.path_pattern, "*") &&
      startswith(local.route_prefixes[j], local.route_prefixes[i])
    ]
  ])
}

###############################################################################
# PrivateLink
###############################################################################

resource "aws_vpc_endpoint" "execute_api" {
  count = local.create_endpoint ? 1 : 0

  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${local.region}.execute-api"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.vpc_endpoint_subnet_ids
  security_group_ids = var.vpc_endpoint_security_group_ids

  # Off by default, and this is the consequential setting on the whole endpoint.
  #
  # Private DNS on an execute-api endpoint takes over *.execute-api.<region>.
  # amazonaws.com for the ENTIRE VPC. Every caller in that VPC then resolves every
  # API Gateway hostname to this endpoint, including APIs that are still regional,
  # in other accounts, or owned by other teams, and those calls start returning 403.
  # That breaks exactly the phased migration this design depends on, where regional
  # APIs keep working while private ones are cut over one at a time.
  #
  # The private custom domain name is what makes it unnecessary: consumers call the
  # friendly hostname, which resolves through the module's own zone.
  private_dns_enabled = var.enable_endpoint_private_dns

  tags = merge(local.tags, { Name = "${var.name}-execute-api" })

  lifecycle {
    precondition {
      condition     = length(var.vpc_endpoint_subnet_ids) >= 2
      error_message = "Supply at least two subnets in different Availability Zones, or the endpoint is a single-AZ dependency for every internal caller."
    }

    precondition {
      condition     = length(var.vpc_endpoint_security_group_ids) > 0
      error_message = "An interface endpoint with no security group falls back to the VPC default, which is rarely what was intended."
    }
  }
}

###############################################################################
# The API
#
# PRIVATE endpoint type plus a resource policy naming the endpoint. Both are
# needed: the endpoint type removes the public route, and the policy is what
# stops any other VPC endpoint in the account from calling in.
###############################################################################

locals {
  # A ternary cannot mix an object and a string, so the two shapes an IAM
  # Principal can take are built separately and merged into the statement.
  allow_principal = length(var.allowed_principal_arns) > 0 ? jsonencode({ AWS = var.allowed_principal_arns }) : jsonencode("*")

  api_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AllowCallsThroughThePermittedEndpoint"
          Effect    = "Allow"
          Principal = jsondecode(local.allow_principal)
          Action    = "execute-api:Invoke"
          Resource  = "execute-api:/*"
        },
        {
          # Explicit deny, not merely an absent allow. Without it, an identity
          # policy elsewhere in the account granting execute-api:Invoke would be
          # enough to call the API from any endpoint.
          Sid       = "DenyCallsFromAnyOtherEndpoint"
          Effect    = "Deny"
          Principal = "*"
          Action    = "execute-api:Invoke"
          Resource  = "execute-api:/*"
          Condition = {
            StringNotEquals = { "aws:SourceVpce" = local.endpoint_id }
          }
        },
      ],
    )
  })
}

resource "aws_api_gateway_rest_api" "this" {
  name        = var.name
  description = "Private API for ${var.hostname}"
  tags        = local.tags

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [local.endpoint_id]
  }

  policy = local.api_policy

  lifecycle {
    precondition {
      condition     = length(local.shadowed_routes) == 0
      error_message = <<-EOT
        A path route is shadowed by an earlier, more general one.

        CloudFront evaluates ordered cache behaviors first-match-wins, so the shadowed
        route never receives traffic. Nothing in the plan diff or the console indicates
        this; list specific patterns before general ones.

        ${join("\n        ", local.shadowed_routes)}
      EOT
    }

    precondition {
      condition     = !local.public_front_door || var.certificate_arn != null
      error_message = "certificate_arn (in us-east-1) is required when exposure is \"dual\"."
    }

    precondition {
      condition     = !local.public_front_door || var.origin_secret_arn != null
      error_message = <<-EOT
        origin_secret_arn is required when exposure is "dual".

        The origin header value comes from Secrets Manager rather than a variable, so
        that it never sits in version control and rotating it is a secret update rather
        than a code change. It does still reach the Terraform state, because CloudFront
        takes a custom header only as a literal; the state file is part of the trust
        boundary for this control.
      EOT
    }

    precondition {
      condition     = !local.public_front_door || var.cloudfront_origin_domain != null
      error_message = "cloudfront_origin_domain is required when exposure is \"dual\"."
    }

    precondition {
      condition     = length(local.unreachable_origins) == 0
      error_message = <<-EOT
        A CloudFront origin points at an internal load balancer with no VPC origin.

        AWS names an internal ALB "internal-<name>-<id>.<region>.elb.amazonaws.com",
        and that name does not resolve on the public internet. CloudFront accepts the
        distribution and then fails to connect to the origin on every request. Give the
        origin an entry in cloudfront_vpc_origin_ids.

        ${join("\n        ", local.unreachable_origins)}
      EOT
    }
  }
}

###############################################################################
# Split-horizon DNS
#
# The same hostname, answered differently depending on where the caller is. This
# is what makes the migration cheap: internal consumers change nothing, and each
# cutover is a DNS change that reverses in minutes.
###############################################################################

resource "aws_route53_zone" "private" {
  count = local.create_private_zone ? 1 : 0

  name    = local.zone_name
  comment = "Split-horizon zone for ${var.hostname}"
  tags    = local.tags

  vpc {
    vpc_id = var.vpc_id
  }

  lifecycle {
    # Terraform manages only the VPC associations it created. An association added
    # from another account, which is how a shared services VPC usually joins, would
    # otherwise be removed on the next apply.
    ignore_changes = [vpc]

    # A zone named for a bare public suffix, or for a registrable apex, answers for
    # everything beneath it inside the VPC. The zone this module creates is the
    # hostname itself, so this only catches a hostname that is already too broad.
    precondition {
      condition     = length(split(".", var.hostname)) >= 3
      error_message = "hostname \"${var.hostname}\" is an apex, so a private zone for it would answer for every name beneath it inside the VPC. Use a hostname with a subdomain, or supply private_hosted_zone_id."
    }
  }
}

data "aws_vpc_endpoint" "execute_api" {
  id = local.endpoint_id

  depends_on = [aws_vpc_endpoint.execute_api]
}

###############################################################################
# Private custom domain name
#
# A DNS record alone does not make api.example.com reach a private API. Pointing
# it at the interface endpoint delivers the request, and then API Gateway has no
# way to decide which API it is for: a private API is addressed by its execute-api
# name, or by an x-apigw-api-id header, neither of which a consumer sends when it
# calls the friendly hostname. The request gets a 403.
#
# A PRIVATE custom domain name is what closes that gap. API Gateway matches the
# SNI name against the registered domain, the access association tells it which
# endpoint may present that name, and the base path mapping says which API and
# stage it resolves to. Only then does the record below route anything.
#
# This is also what makes the split-horizon claim true rather than aspirational:
# the same hostname works from inside the VPC and, through CloudFront, from
# outside, and an internal consumer changes nothing during the migration.
###############################################################################

resource "aws_api_gateway_domain_name" "private" {
  count = var.create_private_domain_name ? 1 : 0

  domain_name = var.hostname

  # certificate_arn, not regional_certificate_arn. CreateDomainName uses
  # certificateArn for edge-optimized AND private endpoints; regionalCertificateArn
  # belongs to REGIONAL. The provider accepts either field for any endpoint type, so
  # the wrong one is only rejected by the API at apply.
  certificate_arn = var.private_certificate_arn
  security_policy = "TLS_1_2"
  tags            = local.tags

  endpoint_configuration {
    types = ["PRIVATE"]
  }

  # A private domain name carries its own resource policy, evaluated before the
  # API's. Without it the domain is reachable from any endpoint associated with
  # it, which reopens the hole the API policy closes one layer down.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowThePermittedEndpoint"
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceVpce" = local.endpoint_id }
        }
      },
      {
        # The same reasoning as the API's policy, applied one layer up. An Allow
        # on its own is not a control: a caller arriving through some other
        # associated endpoint, holding an identity policy that grants
        # execute-api:Invoke, is not denied by an allow it simply does not match.
        Sid       = "DenyEveryOtherEndpoint"
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "*"
        Condition = {
          StringNotEquals = { "aws:SourceVpce" = local.endpoint_id }
        }
      },
    ]
  })

  lifecycle {
    precondition {
      condition     = var.private_certificate_arn != null
      error_message = <<-EOT
        private_certificate_arn is required for the private custom domain name.

        It is a REGIONAL certificate in this API's Region, not the us-east-1 one
        CloudFront uses. The two are separate certificates for the same hostname.
      EOT
    }
  }
}

# Names which VPC endpoint is allowed to present this domain name. Without it the
# domain exists and resolves, and every call returns 403.
resource "aws_api_gateway_domain_name_access_association" "private" {
  count = var.create_private_domain_name ? 1 : 0

  domain_name_arn                = aws_api_gateway_domain_name.private[0].arn
  access_association_source      = local.endpoint_id
  access_association_source_type = "VPCE"
  tags                           = local.tags
}

# The stage belongs to whoever defines the API's methods, so it is a name here
# rather than a reference. Null leaves the domain name unmapped, which is the
# right state while the API body is still being built elsewhere.
resource "aws_api_gateway_base_path_mapping" "private" {
  count = var.create_private_domain_name && var.api_stage_name != null ? 1 : 0

  api_id         = aws_api_gateway_rest_api.this.id
  stage_name     = var.api_stage_name
  domain_name    = aws_api_gateway_domain_name.private[0].domain_name
  domain_name_id = aws_api_gateway_domain_name.private[0].domain_name_id
}

locals {
  endpoint_dns_entries = tolist(data.aws_vpc_endpoint.execute_api.dns_entry)

  # An interface endpoint publishes a Region-wide DNS name plus one per AZ, and AWS
  # documents no ordering for them. Taking entry [0] therefore picks a zonal name on
  # some applies and the regional one on others, which turns the record into a
  # single-AZ dependency that nothing in the plan reveals.
  #
  # The zonal names are the regional name with an AZ inserted, so the regional entry
  # is the shortest. That is a property of the names themselves rather than of the
  # order they arrive in.
  endpoint_regional_dns = [
    for e in local.endpoint_dns_entries : e
    if length(e.dns_name) == min([for x in local.endpoint_dns_entries : length(x.dns_name)]...)
  ][0]
}

resource "aws_route53_record" "private" {
  count = var.create_dns_records ? 1 : 0

  zone_id = local.private_zone_id
  name    = var.hostname
  type    = "A"

  alias {
    name                   = local.endpoint_regional_dns.dns_name
    zone_id                = local.endpoint_regional_dns.hosted_zone_id
    evaluate_target_health = false
  }

  lifecycle {
    # The record resolves the hostname to the endpoint. What makes the endpoint
    # answer for that hostname is the domain name above, so publishing the record
    # without it produces a name that resolves and then 403s on every call, which
    # is a harder failure to read than one that does not resolve at all.
    precondition {
      condition     = var.create_private_domain_name || var.private_domain_name_id != null
      error_message = <<-EOT
        The private record would resolve api.example.com to the interface endpoint,
        and API Gateway would then have no way to tell which private API the request
        is for. Every call returns 403.

        Either let the module create the private custom domain name, or set
        private_domain_name_id to one that already exists, or set
        create_dns_records = false and publish the record where the domain name lives.
      EOT
    }
  }
}

resource "aws_route53_record" "public" {
  count = var.create_dns_records && local.create_distribution ? 1 : 0

  zone_id = var.public_hosted_zone_id
  name    = var.hostname
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.this[0].domain_name
    zone_id                = aws_cloudfront_distribution.this[0].hosted_zone_id
    evaluate_target_health = false
  }

  lifecycle {
    precondition {
      condition     = var.public_hosted_zone_id != null
      error_message = "public_hosted_zone_id is required when exposure is \"dual\" and create_dns_records is true."
    }
  }
}
