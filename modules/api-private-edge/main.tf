###############################################################################
# A private API Gateway reached through PrivateLink, with split-horizon DNS and
# an optional CloudFront front door for callers outside the network.
#
# The problem this addresses: a regional execute-api endpoint stays publicly
# resolvable even when CloudFront, Shield and a global WAF sit in front of it,
# so every edge protection can be skipped with one curl against the regional
# URL. The real security posture becomes whatever the regional WAF enforces.
#
# Making the API PRIVATE removes the public endpoint entirely. The bypass is not
# blocked by a rule someone could misconfigure; there is nothing left to reach.
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

  # The apex of the hostname, used when the module creates the private zone.
  zone_name = join(".", slice(split(".", var.hostname), 1, length(split(".", var.hostname))))

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

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${local.region}.execute-api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.vpc_endpoint_subnet_ids
  security_group_ids  = var.vpc_endpoint_security_group_ids
  private_dns_enabled = true

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

        The origin header value must come from Secrets Manager rather than a literal:
        a literal is written to the Terraform state and to the distribution config, and
        the control is worth exactly as much as the secrecy of that value.
      EOT
    }

    precondition {
      condition     = !local.public_front_door || var.cloudfront_origin_domain != null
      error_message = "cloudfront_origin_domain is required when exposure is \"dual\"."
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
  }
}

data "aws_vpc_endpoint" "execute_api" {
  id = local.endpoint_id

  depends_on = [aws_vpc_endpoint.execute_api]
}

resource "aws_route53_record" "private" {
  count = var.create_dns_records ? 1 : 0

  zone_id = local.private_zone_id
  name    = var.hostname
  type    = "A"

  alias {
    name                   = tolist(data.aws_vpc_endpoint.execute_api.dns_entry)[0].dns_name
    zone_id                = tolist(data.aws_vpc_endpoint.execute_api.dns_entry)[0].hosted_zone_id
    evaluate_target_health = false
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
