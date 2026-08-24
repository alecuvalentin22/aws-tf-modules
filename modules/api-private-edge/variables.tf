###############################################################################
# Identity
###############################################################################

variable "name" {
  description = "Base name for the resources this module creates."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,29}$", var.name))
    error_message = "name must be 2-30 characters of lowercase letters, digits and hyphens."
  }
}

variable "hostname" {
  description = <<-EOT
    The hostname consumers call, for example api.example.com.

    The same name is served from two places. Inside the VPC a private hosted zone
    resolves it to the interface endpoint; outside, the public zone resolves it to
    CloudFront. That split is what makes the migration cheap: an internal caller
    changes nothing at all, and each cutover is a DNS change that reverses in minutes.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", var.hostname))
    error_message = "hostname must be a lowercase DNS name."
  }
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}

###############################################################################
# Exposure
###############################################################################

variable "exposure" {
  description = <<-EOT
    Who may call this API.

      internal  The API is PRIVATE. It is reachable only through the VPC interface
                endpoint, and no public execute-api endpoint exists. The bypass that
                this module's whole design is about is not blocked, it is structurally
                impossible: there is no public endpoint to reach.

      dual      The API is still PRIVATE, and CloudFront reaches it from the outside
                through a VPC origin. One API definition, one authorizer, two front
                doors. External callers keep the edge protections; internal callers
                stop leaving the network.

    There is deliberately no "public" option. A regional endpoint left resolvable on
    the internet is the weakness this module exists to remove, and offering it as a
    setting would invite it back in.
  EOT
  type        = string
  default     = "internal"

  validation {
    condition     = contains(["internal", "dual"], var.exposure)
    error_message = "exposure must be \"internal\" or \"dual\"."
  }
}

###############################################################################
# Private access
###############################################################################

variable "vpc_id" {
  description = "VPC that hosts the interface endpoint and the private hosted zone."
  type        = string
}

variable "vpc_endpoint_id" {
  description = <<-EOT
    Existing execute-api interface endpoint to use. Null creates one.

    Sharing a single endpoint across many APIs is usually right: an interface endpoint
    is billed per hour per AZ, so one per API multiplies a fixed cost by the number of
    teams for no benefit.
  EOT
  type        = string
  default     = null
}

variable "vpc_endpoint_subnet_ids" {
  description = "Subnets for a module-created interface endpoint. At least two, in different AZs."
  type        = list(string)
  default     = []
}

variable "vpc_endpoint_security_group_ids" {
  description = "Security groups for a module-created interface endpoint."
  type        = list(string)
  default     = []
}

variable "enable_endpoint_private_dns" {
  description = <<-EOT
    Enable private DNS on a module-created interface endpoint. Off by default, and this
    is the most consequential setting on the endpoint.

    Private DNS on an execute-api endpoint takes over *.execute-api.<region>.amazonaws.com
    for the ENTIRE VPC. Every caller in that VPC then resolves every API Gateway hostname
    to this endpoint, including APIs that are still regional, owned by other teams, or in
    other accounts, and those calls begin returning 403. That breaks the phased migration
    this design depends on, where regional APIs keep working while private ones are cut
    over one at a time.

    The private custom domain name is what makes it unnecessary: consumers call the
    friendly hostname and resolve it through this module's own zone.
  EOT
  type        = bool
  default     = false
}

variable "allowed_principal_arns" {
  description = <<-EOT
    Principals allowed by the API's resource policy, on top of the endpoint condition.
    Empty allows any principal that reaches the API through the permitted endpoint.

    The endpoint condition is the network control. This is the identity control, and
    they are not substitutes for each other.
  EOT
  type        = list(string)
  default     = []
}

###############################################################################
# Private custom domain name
###############################################################################

variable "create_private_domain_name" {
  description = <<-EOT
    Register var.hostname as a PRIVATE custom domain name on this API.

    Without it, a DNS record pointing the hostname at the interface endpoint
    delivers the request and API Gateway then has no way to tell which private API
    it is for, so every call returns 403. A private API is otherwise addressed only
    by its execute-api name or by an x-apigw-api-id header, and a consumer calling
    the friendly hostname sends neither.

    Set false when the domain name is owned by another stack, and supply
    private_domain_name_id so the record can still be published here.
  EOT
  type        = bool
  default     = true
}

variable "private_domain_name_id" {
  description = "Existing private custom domain name to route to, when create_private_domain_name is false."
  type        = string
  default     = null
}

variable "private_certificate_arn" {
  description = <<-EOT
    REGIONAL ACM certificate for the hostname, in this API's Region. Required when the
    module creates the private custom domain name.

    Not the same certificate as certificate_arn: CloudFront reads only from us-east-1,
    API Gateway reads only from its own Region. The same hostname needs both.
  EOT
  type        = string
  default     = null
}

variable "api_stage_name" {
  description = <<-EOT
    Stage the private custom domain name maps to. Null leaves it unmapped.

    A name rather than a reference: this module owns how the API is exposed, not what
    it does, so the methods, the deployment and the stage belong to the caller.
  EOT
  type        = string
  default     = null
}

###############################################################################
# Public front door (exposure = "dual")
###############################################################################

variable "certificate_arn" {
  description = "ACM certificate for the hostname. MUST be in us-east-1: CloudFront reads certificates only from there. Required when exposure is \"dual\"."
  type        = string
  default     = null
}

variable "cloudfront_origin_domain" {
  description = <<-EOT
    Domain CloudFront sends requests to. For a private API this is the private ALB, or
    a VPC origin, that fronts it. Required when exposure is "dual".
  EOT
  type        = string
  default     = null
}

variable "cloudfront_vpc_origin_ids" {
  description = <<-EOT
    origin domain => CloudFront VPC origin ID, for upstreams that are not reachable
    from the internet.

    An internal ALB, which is what fronts a private API, does not resolve publicly.
    CloudFront accepts a distribution pointing at one and then fails to connect on
    every request, which reads as an origin outage rather than a configuration
    mistake. A VPC origin is the supported path in.

    The VPC origin itself is created by the caller, because it needs the load
    balancer's ARN and this module deliberately does not own the load balancer.
  EOT
  type        = map(string)
  default     = {}
}

variable "path_routes" {
  description = <<-EOT
    Path-based routing, as an ordered list. The FIRST match wins, so ordering is
    security configuration rather than cosmetics: a permissive pattern placed above a
    restrictive one takes precedence, and nothing in the console warns about it.

    The module refuses an ordering where a general pattern precedes a more specific one
    that it would shadow, because that mistake is invisible in a plan diff.

    A path prefix routes traffic. It is NOT an authorisation boundary: CloudFront
    normalises the URI when matching but forwards the raw one to the origin, so
    /a/..%2fb can match one behavior and arrive as another. Authorisation belongs in
    the authorizer and in the API's resource policy.
  EOT

  type = list(object({
    path_pattern    = string
    origin_domain   = optional(string)
    allowed_methods = optional(list(string), ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"])
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.path_routes : can(regex("^/", r.path_pattern))
    ])
    error_message = "Each path_pattern must start with a forward slash."
  }

  validation {
    condition     = length(distinct([for r in var.path_routes : r.path_pattern])) == length(var.path_routes)
    error_message = "Duplicate path_pattern entries: the later one would be unreachable."
  }

  # CloudFront accepts exactly three method sets, and rejects anything else at apply.
  # The set must also contain the cached_methods the behavior declares.
  validation {
    condition = alltrue([
      for r in var.path_routes : contains([
        "GET,HEAD",
        "GET,HEAD,OPTIONS",
        "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
      ], join(",", sort(r.allowed_methods)))
    ])
    error_message = "allowed_methods must be exactly [GET,HEAD], [GET,HEAD,OPTIONS], or [GET,HEAD,OPTIONS,PUT,POST,PATCH,DELETE]. CloudFront accepts no other combination and rejects the distribution at apply."
  }
}

variable "origin_secret_header_name" {
  description = <<-EOT
    Header CloudFront injects so the origin can prove the request came through it.

    Paired with a regional WAF that denies by default, this is the standard mitigation
    for the regional-endpoint bypass, and it holds for exactly as long as the secret
    does. It is a transitional control: the real fix is that a private API has no
    public endpoint at all.
  EOT
  type        = string
  default     = "x-origin-verify"
}

variable "origin_secret_arn" {
  description = <<-EOT
    Secrets Manager secret holding the origin header value. Required when exposure is
    "dual".

    Worth being precise about what this buys, because it is less than it looks.
    CloudFront takes a custom header only as a literal string, so the module reads the
    secret and the plaintext lands in the Terraform state either way. The state file is
    part of the trust boundary for this control; encrypt it and restrict who can read
    it. What the indirection does buy is that the value never sits in version control,
    and that rotating it is a secret update rather than a code change.

    Rotate with the overlap procedure: add the new value to the WAF allow list, update
    the origin header, wait for the distribution to finish deploying, then remove the
    old value. Rotating without the overlap is a full outage, and it is the step that
    gets skipped.
  EOT
  type        = string
  default     = null
}

variable "web_acl_arn" {
  description = "WebACL to associate with the distribution. MUST be scope CLOUDFRONT and created in us-east-1. Null attaches none."
  type        = string
  default     = null
}

###############################################################################
# DNS
###############################################################################

variable "private_hosted_zone_id" {
  description = "Existing private hosted zone for the hostname. Null creates one in vpc_id."
  type        = string
  default     = null
}

variable "public_hosted_zone_id" {
  description = "Public hosted zone that resolves the hostname to CloudFront. Required when exposure is \"dual\"."
  type        = string
  default     = null
}

variable "create_dns_records" {
  description = <<-EOT
    Create the DNS records. Set false to stage everything else first and cut over
    separately.

    Worth doing on a first migration: with the records held back, the API, the endpoint
    and the distribution can all be created and verified while live traffic still
    follows the old path. The cutover is then one small change that reverses in minutes.
  EOT
  type        = bool
  default     = true
}
