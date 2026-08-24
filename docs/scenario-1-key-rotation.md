# Scenario 1 - Key rotation on AWS

> A regulator now requires rotation of all KMS keys. Around thirty keys live in a
> dedicated Security account, one per environment/service pair, addressed through
> aliases and consumed cross-account by S3, RDS and DynamoDB. All key material is
> generated on an on-premise HSM and imported (BYOK). Key policies follow least
> privilege.

Answers to the four questions are in order below. The single fact that determines
every answer is stated first, because reading the scenario without it produces a
plan that cannot be executed.

---

## The constraint that decides everything

The keys have `Origin = EXTERNAL`. AWS KMS does not support automatic rotation for
imported key material. There is no flag to enable. Rotation of a BYOK key means:
generate new material on the HSM, wrap it, import it, then call `RotateKeyOnDemand`.
Every cycle, for every key.

So "turn on rotation" is not a configuration change. It is a recurring operational
ceremony, and the work is in making that ceremony safe and repeatable at a scale of
thirty keys.

---

## Q1 - Main challenges and impacts

### 1. The on-demand rotation quota is a hard ceiling - and it sets the policy

A KMS key supports **25 on-demand rotations**, lifetime. Not per year. The quota
cannot be raised.

| Rotation period the regulator settles on | Rotations in 25 years | Key lifetime before the quota is exhausted |
| --- | --- | --- |
| Annual | 25 | 25 years - comfortable |
| Semi-annual | 50 | ~12 years |
| Quarterly | 100 | **~6 years** |
| Monthly | 300 | ~2 years |

This inverts the usual order of the conversation. Normally a rotation period is agreed
and then implemented. Here the rotation period decides whether the existing
key estate survives the policy at all, so it has to be settled **before** any
implementation work starts.

If the answer is quarterly or shorter, the escape route, create a new key, retarget
the alias, retain the old key for decryption of old data, has to be designed in from
the beginning, because it changes the automation, the key policies and the cost model.
Discovering it in year six is a migration project under regulatory pressure.

Impact: a design question that must be answered by the regulator's requirement,
not by the platform team.

### 2. The import window is 24 hours, and nothing can be prepared in advance

Each import needs a fresh wrapping public key and import token from
`GetParametersForImport`. They are valid for 24 hours, they are issued as a pair, and
they must be used together. There is no way to pre-generate material against a token
that does not exist yet.

So the HSM ceremony, the wrap and the import all have to complete inside the same
day. For one key that is a morning. For thirty keys it is either a full day of
error-prone manual work with an HSM operator standing by, or it is automated.

Impact: automation is not an optimisation here, it is what makes the ceremony
feasible at all.

### 3. Custody of old material is permanent - and losing it is unrecoverable

Old key material remains the only thing able to decrypt data encrypted under it.
Rotation does not change that; it adds new material for new encryption and keeps the
old versions for decryption.

If a material version is lost, or is allowed to expire, the KMS key becomes unusable
for that data, permanently. There is no AWS-side recovery, because AWS never held
the material in the clear.

The observable failure is not subtle:

| Service | What happens |
| --- | --- |
| RDS | Instance enters `inaccessible-encryption-credentials` and stops serving |
| DynamoDB | Table becomes inaccessible; requests fail |
| S3 | `GET` on affected objects returns errors |
| EBS | Volumes cannot be attached; instances fail to start |

Two mitigations, both mandatory:

- Import every version with **`KEY_MATERIAL_DOES_NOT_EXPIRE`**. An expiry date on
  imported material is a scheduled outage.
- **Escrow every version ever generated**, in the HSM's own backup domain, with a
  tested restore procedure. The escrow is the disaster recovery plan for the entire
  encrypted estate, so it deserves the same rigour as the data it protects.

Impact: this is the highest-severity risk in the scenario. Every other problem
here is expensive; this one is unrecoverable.

### 4. Rotation is not re-encryption - and this is probably the real question

This is the point most likely to be misunderstood between the regulator and the
platform team, and it is worth settling in writing before anyone commits to a date.

Rotating a key changes which material encrypts **new** data. Existing data stays
wrapped under the material that encrypted it. A fully rotated estate can therefore
still be entirely protected by last year's key material, which is very often not what
"rotate everything" was intended to mean.

| What the regulator may mean | What it costs |
| --- | --- |
| New material in use for new writes | The ceremony described here |
| All data at rest re-encrypted under new material | An order of magnitude more: S3 batch copy of every object, RDS snapshot/restore cycles with downtime, DynamoDB table copies |

Re-encryption is a separate programme with its own budget, its own downtime windows
and its own risk. Committing to a rotation plan without clarifying which one is being
asked for is how a compliance deadline turns into an outage.

Impact: the largest open question in the scenario, and a cost difference of
roughly 10x.

### 5. The good news: applications and Terraform see nothing

Rotation preserves the key ID, the key ARN, the alias, the key policy and all grants.
Consumers reference `alias/prod-s3`; that alias points at the same key before and
after. There is no application change, no config change and no Terraform diff.

The existing discipline of putting aliases in front of every key is what makes this
true, and it is worth saying so explicitly. It is the reason this scenario is an
operations problem rather than a fleet-wide migration.

### Other impacts worth listing

- **Cross-account consumers.** The keys are consumed cross-account. Key policies and
  grants survive rotation untouched, so no consumer-side change is needed, but this
  should be verified in dev rather than assumed, because a broken grant is discovered
  by an outage.
- **Cost.** Each additional material version is billed as a key version. Thirty keys
  rotating annually is a rounding error; thirty keys rotating monthly is not.
- **Audit evidence.** The regulator will ask for proof of rotation, not a claim.
  `ListKeyRotations` and CloudTrail `ImportKeyMaterial` / `RotateKeyOnDemand` events
  are the evidence; they need to be collected and retained deliberately.

---

## Q2 - Steps to apply rotation

Two phases: a one-off design decision, then a repeatable per-key ceremony.

### Phase 0 - before any key is touched

1. Confirm with the regulator whether **rotation** or **re-encryption** is required
   (Q1.4). Get it in writing.
2. Fix the rotation period, and check it against the 25-rotation quota (Q1.1).
   Document the alias-retarget escape route if the period is quarterly or shorter.
3. Confirm the HSM escrow procedure works by **restoring** a test material version,
   not by asserting that backups exist.
4. Build the inventory: every key, its aliases, its consumers, its grants, its
   current material version. Roughly thirty keys, small enough to enumerate exactly,
   and there is no excuse for not doing so.

### Phase 1 - the per-key ceremony

```
  HSM (on-premise)                    AWS KMS (Security account)
  -----------------                   --------------------------
  1. Generate new key material
     inside the HSM. It never
     leaves in the clear.
                                      2. GetParametersForImport
                                         - RSA_4096
                                         - RSAES_OAEP_SHA_256
                                         returns wrapping public key
                                         + import token (24h validity)
  3. Import the wrapping public
     key into the HSM. Wrap the
     new material with it, using
     the HSM's PKCS#11 interface.
                                      4. ImportKeyMaterial
                                         - ImportType: NEW_KEY_MATERIAL
                                         - ExpirationModel:
                                           KEY_MATERIAL_DOES_NOT_EXPIRE
                                         Material is STAGED. Nothing has
                                         changed yet. Fully reversible.
                                      5. Verify: ListKeyRotations shows
                                         the pending version; a test
                                         encrypt/decrypt still succeeds.
                                      6. RotateKeyOnDemand
                                         New material becomes current for
                                         new encryption. Old versions are
                                         retained for decryption.
                                      7. Verify: encrypt/decrypt against
                                         the alias; confirm consumers
                                         (S3/RDS/DynamoDB) are healthy.
```

The property that makes this safe is **step 4**. `ImportKeyMaterial` with
`NEW_KEY_MATERIAL` stages the material without making it current. Nothing observable
changes until step 6. So the expensive, hard-to-repeat part of the ceremony, the HSM
work, is completed and verified before the only irreversible step is taken, and it can
be abandoned at no cost if verification fails.

### Phase 2 - rollout order

`dev -> int -> prod`, with a soak period between environments. Per environment, batch
the keys rather than doing all thirty at once, so that a systemic problem is found on
key three rather than key twenty-nine.

### Phase 3 - what to automate, and what not to

| Step | Automated? |
| --- | --- |
| Inventory and scheduling | Yes - EventBridge Scheduler |
| `GetParametersForImport` | Yes - Step Functions |
| HSM generation and wrap | **No.** Dual-control human ceremony on the HSM |
| `ImportKeyMaterial` | Yes - Step Functions |
| Verification | Yes - encrypt/decrypt probe plus consumer health checks |
| `RotateKeyOnDemand` | Yes, gated on verification passing |
| Evidence capture | Yes - CloudTrail to the audit account |

A Step Functions state machine per key, orchestrated by EventBridge, with a manual
approval task (`waitForTaskToken`) around the HSM ceremony. The state machine handles
the 24-hour token window as an explicit timeout, so an abandoned ceremony fails
cleanly and is retried with a fresh token rather than half-completing.

The HSM ceremony itself stays human and dual-controlled on purpose. It is the one
step where automation would mean giving a machine identity the ability to generate
material for every key in the estate.

---

## Q3 - Monitoring compliance with an AWS managed service

The requirement is subtler than it first appears. The ask is to identify, at any time,
the *resources* that are not compliant: a specific S3 bucket, RDS instance or DynamoDB
table. Not keys.

That distinction rules out the obvious answer.

### Why the AWS managed Config rule is not enough

`cmk-backing-key-rotation-enabled` fails on both counts:

1. Its own documentation states it does **not** apply to keys with imported material.
   Every key in this estate has imported material, so the rule is non-functional here.
2. It evaluates `AWS::KMS::Key` resources. It answers "is this key rotated?", not
   "is this database protected by a rotated key?" - which is what was asked.

Reporting green on a rule that structurally cannot evaluate these keys is worse than
having no rule, because it produces false assurance.

### What to build: a custom AWS Config rule

A custom Config rule backed by Lambda, evaluating the **resource** types, walking the
reference from resource to key to rotation history:

```
  AWS Config records a change to an S3 bucket / RDS instance / DynamoDB table
                                  |
                                  v
                    Custom Config rule (Lambda)
                                  |
              1. Read the resource's KMS key ARN from the
                 configuration item
              2. Resolve the alias to the key
              3. kms:ListKeyRotations on that key
              4. Compare the most recent rotation date against
                 the policy window (e.g. 365 days)
                                  |
                                  v
         COMPLIANT / NON_COMPLIANT, annotated with the key ARN
         and the actual last-rotation date
                                  |
                                  v
        AWS Config aggregator (Security account)  -->  Security Hub
                                  |
                                  v
                      EventBridge --> SNS / ticket
```

Design points that matter:

- **Evaluate resource types, not `AWS::KMS::Key`.** The rule's scope is
  `AWS::S3::Bucket`, `AWS::RDS::DBInstance`, `AWS::DynamoDB::Table`. That is what makes
  the finding say "this table is at risk" rather than "some key is stale".
- **Annotate the finding with the key ARN and the actual last-rotation date.** A
  finding that says only `NON_COMPLIANT` generates a triage task; one that says
  "encrypted by `alias/prod-rds`, last rotated 412 days ago" is directly actionable.
- **Deploy as a conformance pack** via CloudFormation StackSets across the
  organisation, so it lands in every account without per-account work.
- **Aggregate into the Security account**, which is where the keys already live and
  where the compliance view belongs.
- **Handle the AWS-managed-key case explicitly.** A bucket encrypted with `aws/s3`
  rather than a CMK is a different finding from one encrypted with a stale CMK, and
  conflating them will bury the real issue.
- **Cross-account reads.** The rule runs in the workload account but the key lives in
  the Security account, so it needs a read-only role there for `kms:ListKeyRotations`
  and `kms:DescribeKey`. This is the part most likely to be missed at design time.

Supporting services, each doing the job it is actually good at:

| Service | Role |
| --- | --- |
| AWS Config | Resource inventory, change-triggered and periodic evaluation |
| Conformance pack | Org-wide deployment of the rule |
| Config aggregator | Single cross-account, cross-Region compliance view |
| Security Hub | Findings alongside the rest of the security posture |
| EventBridge | Routes `NON_COMPLIANT` to SNS or a ticket |
| CloudTrail | The audit evidence: `ImportKeyMaterial`, `RotateKeyOnDemand` |
| CloudWatch alarm | Fires when a scheduled rotation did **not** happen - silence is the failure mode, so the alarm must treat missing data as breaching |

That last row is the one usually forgotten. Everything above detects a *bad* rotation;
only a staleness alarm detects a rotation that never ran.

---

## Q4 - Securing key material in transit from HSM to KMS

This is the part AWS has already solved, and the correct answer is to use the
protocol as designed rather than to add anything to it.

### The protocol

The KMS import protocol is built so that **plaintext key material never exists outside
an HSM boundary at either end**:

1. `GetParametersForImport` returns a public key whose private half was generated
   inside, and never leaves, an AWS KMS HSM.
2. The material is wrapped with that public key **inside the on-premise HSM**.
3. Only ciphertext crosses the network.
4. KMS unwraps it inside its own HSM.

There is no point in the flow at which the material is in the clear in a general
purpose operating system.

### Choices that matter

| Choice | Value | Why |
| --- | --- | --- |
| Wrapping algorithm | `RSAES_OAEP_SHA_256` | OAEP with SHA-256. Avoid `RSAES_PKCS1_V1_5` - padding-oracle history, and it is offered only for legacy compatibility |
| Wrapping key spec | `RSA_4096` | Largest available; the material is long-lived, so the wrapping strength should outlast it |
| Where the wrap happens | Inside the HSM, via **PKCS#11** | Not with OpenSSL on an operator's laptop. AWS explicitly labels the CLI/OpenSSL flow "proof of concept only", and it means the material touches a general purpose OS, its page file and its shell history |
| Expiration model | `KEY_MATERIAL_DOES_NOT_EXPIRE` | An expiry on imported material is a scheduled, unrecoverable outage (Q1.3) |
| Network path | **KMS VPC interface endpoint (PrivateLink)** over Direct Connect / VPN | The wrapped material never traverses the public internet, and the endpoint policy restricts which key ARNs may be called |
| Ceremony control | Dual control, in a controlled room, on an audited workstation | The HSM is the root of trust for the whole estate; single-operator access to it is the real risk here |

### Pin the algorithm in the key policy

The wrapping algorithm is chosen when the import parameters are requested, not when the
material is imported, so the condition belongs on `GetParametersForImport`:

```json
[
  {
    "Sid": "DenyWeakWrappingAlgorithm",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "kms:GetParametersForImport",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "kms:WrappingAlgorithm": "RSAES_OAEP_SHA_256" }
    }
  },
  {
    "Sid": "DenyWeakWrappingKeySpec",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "kms:GetParametersForImport",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": { "kms:WrappingKeySpec": "RSA_4096" }
    }
  }
]
```

Two statements rather than one, and the reason is the same AND/OR distinction that
decides the resource selection in scenario 4. Condition keys within a single operator
block are **AND**-ed. Writing both keys under one `StringNotEquals` therefore denies
only a request that gets *both* wrong: `RSAES_PKCS1_V1_5` with `RSA_4096` satisfies
the first half of the negation and fails the second, the condition evaluates false,
and the Deny does not fire. The policy reads as though it pins both and in practice
pins neither. Splitting them makes each denial independent, which is what "neither of
these may be weak" actually means.

That is also the direction of failure to watch for: the statement looks stricter than
it is, produces no error, and is only discovered when someone wraps with PKCS#1 v1.5
and the import succeeds.

Attaching this to `kms:ImportKeyMaterial` instead is a trap worth naming, because it looks
correct and is not. `kms:WrappingAlgorithm` is not present in an `ImportKeyMaterial`
request at all, and `StringNotEquals` against an absent context key evaluates to true, so
the Deny would match every import and stop the ceremony for all thirty keys. The same
reasoning applies to any condition intended to constrain rather than describe: check which
request actually carries the key before writing the policy.

`ImportKeyMaterial` has its own conditions worth using, on a separate statement:
`kms:ExpirationModel` to require `KEY_MATERIAL_DOES_NOT_EXPIRE`, and `kms:ValidTo` if a
bounded lifetime is ever deliberately chosen.

The value of both is that KMS enforces them rather than the automation, which is the right
place for the control. The automation is the thing most likely to be compromised.

### What to reject

- Wrapping with OpenSSL outside the HSM, for the reasons above.
- Transporting material on removable media between the HSM and a workstation. It adds
  a plaintext-at-rest step to a protocol specifically designed not to have one.
- Storing the import token or the wrapping key in a general purpose secret store "for
  convenience". They are valid for 24 hours by design; extending their life extends
  the attack window for no benefit.

---

## Summary

The constraint that decides everything is that these keys are BYOK, so AWS will not
rotate them and no flag exists to make it. Rotation becomes a recurring HSM ceremony, and
three things follow from that: the 25-rotation lifetime quota means the rotation period
the regulator picks decides whether the current keys survive the policy at all; the
24-hour import window makes automation mandatory at thirty keys rather than merely
desirable; and losing a material version is unrecoverable, which makes escrow and
`KEY_MATERIAL_DOES_NOT_EXPIRE` non-negotiable. Settle whether "rotate" means rotation or
re-encryption before anything else, because the two differ by roughly an order of
magnitude in cost.

Per key the sequence is: generate inside the HSM, `GetParametersForImport`, wrap inside
the HSM, import as `NEW_KEY_MATERIAL`, verify, then `RotateKeyOnDemand`. The import stages
the material without changing anything, so the expensive part is done and checked before
the only irreversible step. Roll through dev, int and prod, and automate all of it except
the ceremony itself.

For monitoring, the AWS managed rule is no help: it does not apply to imported material
and it evaluates keys rather than resources. A custom Config rule that walks from a
resource to its key to that key's rotation history answers the question that was actually
asked. Ship it as a conformance pack, aggregate in the Security account, route findings
through Security Hub, and alarm on rotations that did not happen.

Transport is the part AWS has already solved. Use the import protocol as designed:
RSA-4096 with `RSAES_OAEP_SHA_256`, wrapping done inside the HSM over PKCS#11 rather than
with OpenSSL on a laptop, over PrivateLink, and pin the algorithm with a condition on
`GetParametersForImport`, which is the request that carries it, so a compromised import
role cannot downgrade it.
