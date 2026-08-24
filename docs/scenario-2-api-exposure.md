# Scenario 2 - Public and private APIs

> Every API, internal or public, is exposed through one hostname. Traffic goes
> CloudFront (+ Shield Advanced + global WAFv2) -> regional WAF -> one of several
> API Gateways -> Lambda or internal ALB/ECS Fargate backends. A single Lambda
> authorizer fronts all of them. All APIs are public "by design", including those
> never used publicly. APIs are built by different teams but exposed through one
> endpoint.

---

A working module implementing the target architecture below is in
[`modules/api-private-edge`](../modules/api-private-edge): a private API reached through
PrivateLink, a private custom domain name, split-horizon DNS, and an optional CloudFront
front door. Of the four CloudFront traps in Q3, ordering is enforced by a plan-time
precondition; caching and the Host header are pinned in the module rather than left as
inputs; and the fourth, that a path prefix is not an authorisation boundary, is a
property of the request that no Terraform can check, so it is documented on the input
and belongs to the authorizer.

---

## Q1 - Weaknesses in the current architecture

### 1. The edge can be bypassed entirely - this is the critical one

The regional API Gateway endpoints remain publicly resolvable. Anything an attacker
can reach directly with `curl https://{api-id}.execute-api.{region}.amazonaws.com/...`
skips every control bought at the edge:

- Shield Advanced
- The global WAFv2 WebACL, its managed rule groups, bot control and geo-blocking
- CloudFront's own rate limiting and caching

The diagram in the brief shows exactly this path, with an "Attacker" arrow going
straight to the regional endpoint.

The consequence is worth stating plainly: **the real security posture of the platform
is whatever the regional WAF enforces, not what the edge enforces.** Everything else
is optional from an attacker's point of view. That also means the Shield Advanced and
bot-control spend is buying materially less than the architecture diagram implies.

### 2. Internal traffic leaves AWS to come back

Service-to-service calls between internal applications currently resolve the public
hostname, egress to the internet, reach CloudFront at an edge location, and come back
into the same Region.

That costs, in order of how much they will actually be noticed:

- **Latency** - tens of milliseconds added to every internal hop, on a path that
  could be single-digit.
- **Money** - CloudFront request and data-transfer charges, NAT gateway egress, and
  WAF request charges paid twice (global and regional) on traffic that never needed
  to leave.
- **A data-flow story that is hard to defend.** In a regulated business, "internal
  application traffic transits the public internet" is a sentence that costs a lot of
  meeting time with a regulator, regardless of the fact that it is TLS-encrypted.

### 3. Internal-only APIs are reachable from the internet

APIs that exist purely for internal integration are exposed publicly. Their entire
legitimate traffic comes from inside the network, which means **any public request to
them is, by definition, either an attack or a misconfiguration.** They are attack
surface with no corresponding benefit.

This is also the easiest thing on this list to fix, and the fix has no consumer
impact.

### 4. One distribution, one WebACL, one hostname, many teams

A single CloudFront distribution and a single WebACL shared by every team gives:

- **One blast radius.** A bad WAF rule, a distribution config error, or a certificate
  problem takes down every API at once.
- **One change bottleneck.** Every team's edge change queues behind every other
  team's, through whoever owns the distribution.
- **No per-API tuning.** Rate limits, caching and geo rules that suit a public
  customer-facing API are wrong for an internal batch integration, and vice versa.

This is the direct opposite of the "APIs as a product" premise, where each team owns
its API end to end.

### 5. A single Lambda authorizer is a shared availability and blast-radius risk

All APIs authenticate through one Lambda authorizer:

- A traffic spike on **any one** API consumes shared Lambda concurrency and throttles
  authentication for **all** of them.
- Its failure mode is a choice between two bad outcomes: fail closed and the whole
  platform is down; fail open and the whole platform is unauthenticated.
- One team's change to the authorizer affects every other team's API.
- Its blast radius on compromise is every API on the platform.

Authorizer result caching mitigates the throttling but does not change the
concentration of risk.

### Also worth flagging

- **No mTLS or client identity at the edge** for partner/broker integrations, which
  are exactly the callers where a stronger client identity is warranted.
- **Uniform egress**: backend ALBs and Lambdas sit behind one shared path, so
  per-API network segmentation is limited.
- **Observability is per-distribution, not per-API**, which makes attribution during
  an incident slow.

---

## Q2 - Target architecture: private internal APIs, minimal impact

### The design

Two changes, and the second is what makes the first cheap:

1. **Make the APIs private.** Convert internal API Gateways to `PRIVATE` endpoint
   type, reached through a **VPC interface endpoint for `execute-api` (PrivateLink)**,
   with a resource policy that permits only that endpoint.
2. **Split-horizon DNS.** A private Route 53 hosted zone for the same hostname,
   resolving to the interface endpoint from inside the VPC. The public zone continues
   to resolve to CloudFront.

```
                 EXTERNAL CALLER                    INTERNAL CALLER
                 (customer, broker)                 (service in the VPC)
                        |                                   |
                        v                                   |
              public DNS: api.example.com                   |
                        |                                   v
                        v                        private zone: api.example.com
                   CloudFront                                |
                 Shield Advanced                              v
                 global WAFv2                        VPC interface endpoint
                        |                              (PrivateLink)
                        v                                    |
                  regional WAF                               |
                        |                                    |
                        +--------------+---------------------+
                                       v
                          API Gateway  (PRIVATE)
                       resource policy: this VPCE only
                                       |
                                       v
                         Lambda / internal ALB -> ECS
```

Same hostname, different answer depending on which resolver the caller hits. Internal
consumers never learn that anything moved.

### Why this is the low-impact option

| Consumer | What changes |
| --- | --- |
| Internal service | **Nothing.** Same hostname, same URL, same TLS certificate. The DNS answer changes. |
| External customer | **Nothing.** Still CloudFront. |
| API team | Endpoint type + resource policy. No application change. |

Each cutover is a DNS change. If anything looks wrong, it is reverted in minutes by
removing a record, no redeploy, no rollback of application code. That property is
what makes it realistic to migrate a large number of APIs without a change freeze.

### APIs that must serve both audiences

Keep **one private API** with two front doors:

```
   External:  CloudFront --> CloudFront VPC origin --> private ALB --> private API GW
   Internal:  VPC interface endpoint ------------------------------> private API GW
```

CloudFront VPC origins (or a VPC Lattice / ALB path) let CloudFront reach into the
VPC without the API being public. There is exactly one API definition, one authorizer
attachment and one deployment.

One detail decides whether the internal half of that picture works at all. A
private hosted zone resolving `api.example.com` to the interface endpoint delivers
the request, and API Gateway then has no way to tell which private API it is for:
a private API is addressed by its `execute-api` name or by an `x-apigw-api-id`
header, and a consumer calling the friendly hostname sends neither. Every call
returns 403 from a name that resolves perfectly, which is a bad failure to debug
because DNS, the endpoint and the API all look healthy.

**Private custom domain names** close it. API Gateway matches the SNI name against
the registered domain, a domain-name access association says which VPC endpoint may
present that name, and a base path mapping says which API and stage it resolves to.
The domain name carries its own resource policy, evaluated before the API's, so it
needs the `aws:SourceVpce` condition as well; without it the domain is reachable
from any endpoint associated with it, which reopens one layer up the hole the API
policy closes. Before this existed the only options were exposing `execute-api`
names to consumers or running a reverse proxy, and both are why teams reached for a
regional endpoint in the first place.

The security property this buys is the important part, stated precisely. Once the API
is `PRIVATE` the `execute-api` name still resolves publicly and answers 403; what no
longer exists is any path to invoke the API through it. The bypass in Q1.1 is then not
blocked by a rule that someone could misconfigure, it has nowhere to arrive. That is a
categorically stronger guarantee than any mitigation in Q4, and it is worth having the
distinction ready, because "the endpoint is gone" is the version that gets challenged.

### The cheaper stepping stone, and its cost

Publishing the same OpenAPI definition twice, once `PRIVATE` and once `REGIONAL`, is
less work and lets internal traffic go private immediately. But the regional endpoint
stays public, so **every bypass mitigation in Q4 remains mandatory**, and the estate
now has two deployments to keep in sync. Worth it as a transitional step for a
high-traffic API; not worth it as a destination.

### Per-team ownership

While the endpoint types are changing anyway, this is the moment to split the shared
distribution: one distribution and WebACL per team or per API product, with the
platform team owning a reusable module rather than the resources themselves. It
removes the shared blast radius and the change bottleneck from Q1.4 at no extra
migration cost, because the consumers are being touched regardless.

Similarly, move from one shared Lambda authorizer to a per-API authorizer (or, better,
an API Gateway JWT authorizer where the identity provider issues standard JWTs, which
removes the Lambda from the request path entirely).

### Sequencing

| Phase | Work | Risk |
| --- | --- | --- |
| 0 | **Measure.** Enable API Gateway access logs and count requests arriving at the regional endpoint that did not come via CloudFront. Right now nobody knows the size of the bypass problem. | None |
| 1 | Quick mitigations (Q4): secret header + regional WAF default-deny | Low |
| 2 | Internal-only APIs -> private + split-horizon DNS | Low; DNS-reversible |
| 3 | Dual-exposure APIs -> private + CloudFront VPC origin | Medium |
| 4 | Per-team distributions, per-API authorizers | Medium |

Phase 0 first, always. The current architecture cannot answer how much bypass
traffic is arriving, and that number determines how urgent phases 1-3 are.

---

## Q3 - Path-based routing to multiple API Gateways in CloudFront

Mechanically this is just **origins + ordered cache behaviors**, and the ordering is
the part that matters.

```
CloudFront distribution - api.example.com
|
+-- origin: policies-api    -> {id1}.execute-api.eu-central-1.amazonaws.com
+-- origin: claims-api      -> {id2}.execute-api.eu-central-1.amazonaws.com
+-- origin: partners-api    -> {id3}.execute-api.eu-central-1.amazonaws.com

ordered cache behaviors - FIRST MATCH WINS
  1. /policies/*   -> policies-api
  2. /claims/*     -> claims-api
  3. /partners/*   -> partners-api
  default (*)      -> policies-api  (or an explicit 403)
```

### The four things that reliably go wrong

1. Forwarding the viewer `Host` header breaks `execute-api` immediately.
API Gateway routes on the `Host` header. Forward `api.example.com` to an
`execute-api` origin and it returns 403 on every request, because that host does not
match the API's expected domain. Use the managed origin request policy
`AllViewerExceptHostHeader`. This is the single most common cause of "CloudFront in
front of API Gateway returns 403".

2. Behavior ordering is security configuration, not cosmetics.
First match wins. A permissive behavior placed above a restrictive one takes precedence,
and nothing in the console warns about it. Specific patterns must be listed before
general ones, and the ordering belongs under change control and code review like any
other security rule.

3. A path prefix is not an authorisation boundary.
CloudFront normalises the URI for **matching** but forwards the **raw** URI to the
origin. So `/policies/..%2fclaims/x` may match the `/policies/*` behavior while the
origin sees something else. Path prefixes route traffic; they must never be the thing
that decides who is allowed to call what. Authorisation belongs at the authorizer and
in the API's own resource policy.

4. Caching must be disabled explicitly.
API responses here are per-caller. Use the managed `CachingDisabled` policy on API
behaviors. The failure mode of getting this wrong is one customer receiving another
customer's response, which surfaces as a data breach rather than as a bug.

### Also

- Per-behavior WAF is not possible: **the WebACL is per-distribution.** Per-API rules
  need either scope-down statements inside the shared WebACL, or separate
  distributions, which is another argument for the per-team split in Q2.
- Origin timeouts default to 30s; long-running APIs need this raised deliberately.
- `/*` as the default behavior should point somewhere safe, or return 403. Defaulting
  to a real API means a typo'd path reaches a real backend.

---

## Q4 - Preventing bypass of CloudFront/WAF to regional endpoints

Ranked by how much they actually protect, which is not the order they are usually
presented in.

### Tier 1 - Remove the public endpoint (the only real fix)

Make the API `PRIVATE`, as in Q2. The regional `execute-api` endpoint ceases to exist.
There is no bypass to block because there is no endpoint to reach.

There is also a cheaper version of the same idea that does not require going private.
A REGIONAL API with a custom domain can set **`disable_execute_api_endpoint = true`**,
which switches off the default `{api-id}.execute-api.{region}.amazonaws.com` hostname
while the API stays reachable through the custom domain. The bypass target stops
existing without the migration; the API is still regional and still public at its custom
domain, so the edge protections still have to be enforced somewhere. It is the right
first move on any API that already has a custom domain, and it takes one argument.

Every option below is a mitigation for the case where neither has been done. They should
be treated as transitional, with a date attached.

### Tier 2 - Shared secret header + regional WAF default-deny

The standard AWS pattern, and the strongest available while the endpoint stays public:

1. CloudFront injects a custom origin header, e.g. `X-Origin-Verify: <secret>`.
2. The regional WAFv2 WebACL on the API Gateway stage **denies by default** and allows
   only requests carrying the correct header value.

```
   Attacker -> regional endpoint directly -> no header -> WAF blocks
   CloudFront -> regional endpoint -> header present -> WAF allows
```

It holds exactly as long as the secret does, so:

- Store it in **Secrets Manager** and read it from there, while being honest about
  what that does and does not buy. CloudFront accepts an origin custom header only as
  a literal string, so the value is in the distribution config unavoidably, and any
  Terraform that reads the secret writes the plaintext into state. What the
  indirection actually buys is that the value never enters version control and that
  rotating it is a secret update rather than a code change. The state file is part of
  the trust boundary for this control; encrypt it and restrict who can read it.
- **Rotate it with the documented overlap procedure**: add the new value to the WAF
  allow-list, update the CloudFront origin header, wait for the distribution to fully
  deploy, then remove the old value. Rotating without the overlap causes a full
  outage. This is the step that gets skipped.
- Alarm on blocked requests at the regional WAF: a sustained non-zero rate is either
  an attacker probing or a rotation that half-completed.

### Tier 3 - restrict source IPs to CloudFront's origin-facing ranges

The intent is to accept only traffic arriving from CloudFront. Two things about how
this is written are worth getting right, because the obvious form does not work.

**A managed prefix list cannot be named in a resource policy.** Prefix lists are
referenceable from security groups and route tables. IAM condition keys are not among
their consumers, and `aws:SourceIp` takes CIDR values only, so a policy naming
`com.amazonaws.global.cloudfront.origin-facing` is not a stricter policy, it is a
broken one. The workable forms are to expand the prefix list into CIDRs at plan time
via the `aws_ec2_managed_prefix_list` data source and template them into the policy,
or to keep the check in WAF with an IPSet. Either way it needs re-planning when AWS
changes the ranges, which is the maintenance cost of this tier.

**And it is weaker than it looks even when written correctly**: it proves the request
came from **a** CloudFront distribution, not from **ours**. An attacker can put their
own distribution in front of the regional endpoint and satisfy it. Worth having as a
layer stacked on Tier 2, never on its own.

### Tier 4 - Detection

Assume a bypass will eventually work and make it visible:

- Log the presence of the verification header in API Gateway access logs and alarm on
  requests without it.
- Compare CloudFront request counts against API Gateway request counts. A sustained
  gap is bypass traffic, and it is the only measurement that quantifies the problem.
- Route the finding to Security Hub rather than to a dashboard nobody opens.

### Summary

| Tier | Control | Strength | Effort |
| --- | --- | --- | --- |
| 1 | Private API + PrivateLink | **Structural** - no endpoint to bypass | Medium |
| 1b | `disable_execute_api_endpoint` on a regional API with a custom domain | Structural for the default hostname; the custom domain stays public | **Very low** |
| 2 | Secret header + WAF default-deny | Strong while the secret holds | Low |
| 3 | CloudFront origin-facing CIDRs, expanded from the prefix list | Weak alone - proves "a" distribution, not ours | Low |
| 4 | Bypass detection and alarming | Detective, not preventive | Low |

The honest recommendation: ship Tiers 2-4 within weeks because they are cheap, and
treat them as scaffolding with a removal date on it.
