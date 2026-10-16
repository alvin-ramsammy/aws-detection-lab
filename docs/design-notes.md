# Design notes

These are the decisions behind the code, and the tradeoffs. Use them as raw material for the phase writeups, and to answer "why did you do it this way?"

## Phase 2: Infrastructure as code

**Two Terraform roots, not one.** Account-wide protections like the S3 public access block are *resources* in Terraform, and destroying a resource turns the protection off. If the baseline lived in the lab root, every `terraform destroy` would quietly undo Phase 1. So `envs/account` is applied once, and `envs/lab` is the destroyable part.

**`allowed_account_ids` on the provider.** Terraform refuses to touch any account but the lab, which guards against applying with the wrong profile.

**The admin IAM user and root aren't in Terraform.** The identity that runs Terraform shouldn't be managed by that same Terraform: one bad apply can lock you out. They remain console-managed from Phase 1.

**IMDSv2 required by default** (`aws_ec2_instance_metadata_defaults`). IMDSv1 is what turns an SSRF bug into stolen instance credentials (the Capital One breach). This one setting kills the bug class for every instance in the region.

**Public subnet, no NAT gateway.** A NAT gateway costs ~$32/month, more than everything else combined. The instance has *no* inbound rules and is reached through SSM Session Manager, so a public subnet doesn't expose it.

## Phase 3: Telemetry

**A multi-region trail even though the lab is single-region.** Attackers with stolen keys love regions nobody watches. A multi-region trail still *records* activity there (searchable in Athena), even though the EventBridge rules only *alert* in us-east-1 (see the known gaps below).

**Log file validation on, SSE-S3 instead of KMS.** Validation gives tamper evidence (`aws cloudtrail validate-logs`) for free. A customer-managed KMS key would add $1/month and key-policy complexity for little gain in a single-account lab. In production, logs would go to a separate log-archive account with Object Lock.

**Athena with partition projection, not OpenSearch or a SIEM.** Zero cost when idle, no crawlers, and no partitions to maintain. The workgroup cancels any query that scans more than 1 GB.

**GuardDuty with the paid add-ons explicitly disabled.** Foundational detection plus S3 data events covers this lab's attacks. EKS, RDS, Lambda, malware and runtime protection are off so the bill doesn't change when the trial ends.

**Security Hub without standards.** The compliance standards need AWS Config recording, which bills per configuration item. Here Security Hub is just the findings aggregator.

## Phase 4: Detection and response

**Detections are data, not code.** Each `detections/rules/*.json` holds metadata (ATT&CK mapping, severity, description) plus the EventBridge pattern and the name of its responder. Terraform loops over the folder, so adding a detection means adding a file.

**Patterns match on success only** (`"errorCode": [{"exists": false}]`). A failed `StopLogging` is interesting for hunting, which is why the Athena query includes failures, but it's not something to auto-remediate.

**Some judgement lives in the Lambda, not the pattern.** EventBridge can match "someone called PutBucketPolicy" but not "the policy grants another account access". DL-003, DL-004 and DL-005 match broadly and decide in code. Benign events exit without logging `DETECTION_FIRED`, so they don't count as alerts.

**Responders are narrow and reversible.**
- DL-002 restarts a stopped trail but doesn't recreate deleted things. Recreating is Terraform's job, and a Lambda that recreates resources fights your own `terraform destroy`.
- DL-003 revokes the *specific rule IDs* from the API response, not "every 0.0.0.0/0 rule on the group", so a pre-existing intentional rule isn't collateral damage. Opt-out is the `detlab:allow-public=true` tag.
- DL-004 quarantines the *target* user (AWSDenyAll, keys deactivated, console password removed) and tags it. Nothing is deleted, so a false positive is a two-minute fix.
- DL-005 deletes the bucket policy, except on the lab's own log buckets, where deleting the policy would break CloudTrail delivery. Those only alert.

**Responder roles are least privilege.** The quarantine role can call `iam:AttachUserPolicy` *only* with `AWSDenyAll`, so even a compromised responder can't grant itself admin.

**Protected users.** Your admin user is in `protected_iam_users`: alert, never quarantine. Without this, the first time you create a key for another user you'd lock yourself out. Self-service key rotation (no `userName` in the request) doesn't fire at all.

**One log group, one marker.** Every responder writes `DETECTION_FIRED` JSON to `/detlab/responders`. Phase 5 measures time-to-detect by searching for that line, which makes "did it fire?" a query instead of a judgement call.

**Slack webhook stays out of Terraform state.** Terraform creates the SSM parameter with a placeholder and `ignore_changes` on the value, and the lab root references the parameter by name instead of reading it. The URL only ever exists in SSM and in Lambda memory.

## Known gaps (good material for the Phase 5 "what missed" section)

- **EventBridge rules are regional.** API calls in other regions (for example a `StopLogging` against a regional trail in `eu-west-1`) are recorded by the multi-region trail but don't alert. IAM, STS and console sign-in events are global and arrive in us-east-1, which is the main reason the lab lives there. The fix is EventBridge cross-region forwarding to the lab region.
- **`ModifySecurityGroupRules` isn't covered by DL-003.** It's another way to open a group, so it's a known bypass.
- **DL-004 quarantines the target user, not the actor.** If a stolen admin key creates a backdoor user, the backdoor gets cut off but the stolen key doesn't. GuardDuty may catch the stolen key's anomalous use (DL-006).
- **The account-level S3 public access block rejects public bucket policies before DL-005 sees them.** The "external account" case is the one DL-005 actually catches. That's defence in depth working, and worth saying in the writeup.
- **Read-only calls aren't covered.** Enumeration (`List*`/`Describe*`) is hunted with the `access_denied_by_principal` Athena query rather than alerted on.
