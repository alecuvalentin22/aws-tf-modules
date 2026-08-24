# `api-private-edge`

Scenario 2. A private API Gateway reached through PrivateLink, with split-horizon
DNS and an optional CloudFront front door for callers outside the network.

Design rationale is in [`docs/scenario-2-api-exposure.md`](../../docs/scenario-2-api-exposure.md).
This file is usage.

## The problem it solves

A regional `execute-api` endpoint stays publicly resolvable even with CloudFront,
Shield and a global WAF in front of it. Every edge protection can be skipped with
one `curl` against the regional URL, so the real security posture of the platform
is whatever the *regional* WAF enforces.

Making the API `PRIVATE` removes the public endpoint. The bypass is not blocked by
a rule someone could misconfigure; there is nothing left to reach.

## Usage

```hcl
module "orders_api" {
  source = "./modules/api-private-edge"

  name     = "orders-api"
  hostname = "api.example.com"
  vpc_id   = "vpc-0123456789abcdef0"

  vpc_endpoint_subnet_ids         = ["subnet-a", "subnet-b"]
  vpc_endpoint_security_group_ids = ["sg-0123456789abcdef0"]
}
```

That is the internal-only case. For an API that must also serve external callers:

```hcl
  exposure                 = "dual"
  certificate_arn          = "arn:aws:acm:us-east-1:...:certificate/..."  # us-east-1
  cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
  origin_secret_arn        = "arn:aws:secretsmanager:...:secret:origin-verify"
  public_hosted_zone_id    = "Z0PUBLIC"

  path_routes = [
    { path_pattern = "/api/admin/*" },   # specific first
    { path_pattern = "/api/*" },
  ]
```

The API stays `PRIVATE` in both cases. `dual` adds a front door; it does not add a
public endpoint.

## Split-horizon DNS

One hostname, answered differently depending on where the caller is:

```
  external caller  -> public zone  -> CloudFront -> VPC origin -> private API
  internal caller  -> private zone -> interface endpoint ------> private API
```

This is what makes the migration cheap. An internal consumer changes nothing at
all, and each cutover is a DNS change that reverses in minutes. Set
`create_dns_records = false` to stage everything first and cut over separately.

## What it refuses

Each of these is a configuration AWS accepts and then behaves badly on. None of
them fails at apply time on its own.

| Refused | Because |
| --- | --- |
| A general path pattern listed before a specific one it shadows | CloudFront is first-match-wins, so the shadowed route never receives traffic. Invisible in a plan diff and in the console |
| Duplicate path patterns | The second is unreachable |
| `exposure = "dual"` without `origin_secret_arn` | A literal header value lands in the Terraform state and the distribution config, and this control is worth exactly the secrecy of that value |
| `exposure = "dual"` without a certificate or origin | Would fail at apply with a less useful message |
| An interface endpoint in fewer than two subnets | It becomes a single-AZ dependency for every internal caller |
| An interface endpoint with no security group | It silently falls back to the VPC default |

There is deliberately no `exposure = "public"`. A regional endpoint left resolvable
is the weakness the module exists to remove.

## The four CloudFront traps, handled

1. **Host header.** API Gateway routes on `Host`; forwarding the viewer's value to
   an `execute-api` origin returns 403 on every request. The module pins the
   `AllViewerExceptHostHeader` managed policy. This is the most common cause of
   "CloudFront in front of API Gateway returns 403".
2. **Behavior ordering is security configuration.** Enforced at plan time.
3. **Caching disabled explicitly.** API responses here are per-caller; caching them
   means one customer receiving another's response, which surfaces as a data breach
   rather than a bug.
4. **A path prefix is not an authorization boundary.** CloudFront normalizes the URI
   when matching but forwards the raw one, so `/a/..%2fb` can match one behavior and
   arrive as another. Documented on `path_routes`; nothing in Terraform can enforce
   it. Authorization belongs in the authorizer and the resource policy.

## Resource policy

`PRIVATE` removes the public route. It does not stop a *different* VPC endpoint in
the account from calling in, and an absent allow is not enough, because an identity
policy elsewhere granting `execute-api:Invoke` would suffice. The module writes an
explicit `Deny` on `aws:SourceVpce`, and `api_resource_policy_json` is exposed so
it can be asserted on and read in review.

## Tests

```bash
terraform init && terraform test    # 15 tests, mocked provider, no AWS account
```
