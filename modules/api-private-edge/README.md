# `api-private-edge`

Scenario 2. A private API Gateway reached through PrivateLink, with split-horizon
DNS and an optional CloudFront front door for callers outside the network.

Rationale is in [`docs/scenario-2-api-exposure.md`](../../docs/scenario-2-api-exposure.md);
usage is below.

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

  # REGIONAL, in this API's Region. Not the us-east-1 one CloudFront reads.
  private_certificate_arn = "arn:aws:acm:eu-central-1:...:certificate/..."
  api_stage_name          = "v1"
}
```

That is the internal-only case. For an API that must also serve external callers:

```hcl
  exposure                 = "dual"
  certificate_arn          = "arn:aws:acm:us-east-1:...:certificate/..."  # us-east-1
  cloudfront_origin_domain = "internal-alb.eu-central-1.elb.amazonaws.com"
  origin_secret_arn        = "arn:aws:secretsmanager:...:secret:origin-verify"
  public_hosted_zone_id    = "Z0PUBLIC"

  # An internal ALB does not resolve on the internet, so CloudFront reaches it
  # through a VPC origin rather than as an ordinary custom origin.
  cloudfront_vpc_origin_ids = {
    "internal-alb.eu-central-1.elb.amazonaws.com" = aws_cloudfront_vpc_origin.alb.id
  }

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

### The DNS record on its own is not enough

Pointing `api.example.com` at the interface endpoint delivers the request and then
leaves API Gateway with no way to decide which private API it is for. A private
API is addressed by its `execute-api` name or by an `x-apigw-api-id` header, and a
consumer calling the friendly hostname sends neither, so every call returns 403
from a name that resolves perfectly. It is a bad failure to debug, because DNS,
the endpoint and the API all look healthy.

The missing piece is a **private custom domain name**: API Gateway matches the SNI
name against the registered domain, the access association says which endpoint may
present that name, and the base path mapping says which API and stage it resolves
to. The module creates all three and refuses to publish the record without them.

The domain name carries its own resource policy, evaluated *before* the API's, so
it gets the `aws:SourceVpce` condition too. Otherwise the domain is reachable from
any endpoint associated with it, which reopens one layer up the hole the API policy
closes.

## What it refuses

Each of these is a configuration AWS accepts and then behaves badly on. None of
them fails at apply time on its own.

| Refused | Because |
| --- | --- |
| A general path pattern listed before a specific one it shadows | CloudFront is first-match-wins, so the shadowed route never receives traffic. Invisible in a plan diff and in the console |
| Duplicate path patterns | The second is unreachable |
| `exposure = "dual"` without `origin_secret_arn` | Keeps the header value out of version control and makes rotation a secret update rather than a code change |
| `exposure = "dual"` without a certificate or origin | Would fail at apply with a less useful message |
| An `internal-*` ALB origin with no VPC origin | It does not resolve on the public internet. CloudFront accepts the distribution and then fails to connect on every request, which reads as an origin outage |
| A private DNS record with no private custom domain name | The name resolves and every call returns 403 |
| Creating a private zone for a two-label hostname | The zone would be the public suffix itself and would answer for every name under it inside the VPC |
| An interface endpoint in fewer than two subnets | It becomes a single-AZ dependency for every internal caller |
| An interface endpoint with no security group | It falls back to the VPC default, which is rarely what was meant |

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
4. **A path prefix is not an authorisation boundary.** CloudFront normalises the URI
   when matching but forwards the raw one, so `/a/..%2fb` can match one behavior and
   arrive as another. Documented on `path_routes`; nothing in Terraform can enforce
   it. Authorisation belongs in the authorizer and the resource policy.

## Resource policy

`PRIVATE` removes the public route. It does not stop a *different* VPC endpoint in
the account from calling in, and an absent allow is not enough, because an identity
policy elsewhere granting `execute-api:Invoke` would suffice. The module writes an
explicit `Deny` on `aws:SourceVpce`, and `api_resource_policy_json` is exposed so
it can be asserted on and read in review.

## Tests

```bash
terraform init && terraform test    # 23 tests, mocked provider, no AWS account
```
