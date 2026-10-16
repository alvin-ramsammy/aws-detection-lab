# Phases 2–6: Build It, Wire the Alarms, Then Attack It

*Parts 2–6 of the [aws-detection-lab](../README.md) series: building an AWS detection and response lab from scratch, as code, and attacking it to prove the detections work.*

---


**The result:** 8 of 9 simulated attacks were detected and auto-remediated within **2–11 seconds**. The ninth never got off the ground, because a control from Phase 2 blocked it before any detection was needed.

## Before any of that: getting locked out

Partway through, I lost access to the account. Recovering it changed the plan. An account that has been out of your hands is an account you don't fully trust, so before building anything on it I went through a compromise check:

- confirmed root still had MFA and no access keys
- reviewed every IAM user, access key and "last used" time
- looked for roles trusting outside accounts
- checked billing across *all* regions
- scanned CloudTrail event history for activity I didn't do
- rotated the long-lived CLI key from Phase 1

That's the same playbook as real incident response, just applied to my own account.

## Phase 2: Infrastructure as code

Everything I did by hand in Phase 1 is now Terraform, split into **two root modules**:

| Root | Contents | Lifecycle |
|------|----------|-----------|
| `envs/account` | S3 Block Public Access, default EBS encryption, IMDSv2-required default, IAM password policy, budgets, billing alarm, Slack webhook parameter | Applied once, permanent |
| `envs/lab` | VPC + EC2 workload, logging, GuardDuty, Security Hub, Athena, detections, responders | Applied per session, destroyed after |

The split is the most important design decision in the repo. In Terraform, account-wide protections are *resources*, and destroying a resource turns the protection **off**. If the baseline lived alongside the lab, every `terraform destroy` at the end of a session would quietly undo my account hardening. Now the cheap, permanent protections stay up, and only the parts that cost money get torn down.

Other choices worth calling out:

- **`allowed_account_ids` on the provider.** Terraform refuses to run against any account but the lab. It's a one-line guardrail against applying with the wrong credentials.
- **IMDSv2 required by default, account-wide.** IMDSv1 is how an SSRF bug turns into stolen instance credentials, the pattern behind the Capital One breach. This setting matters again in Phase 5.
- **Public subnet, no NAT gateway.** A NAT gateway costs ~$32/month, more than the rest of the lab combined. The instance has *zero* inbound rules and is reached through SSM Session Manager, so the public subnet doesn't expose it.
- **The identity that runs Terraform isn't managed by Terraform.** My admin IAM user and root stay console-managed, so one bad apply can't lock me out.

## Phase 3: Telemetry

| Source | Configuration | Why |
|--------|---------------|-----|
| CloudTrail | Multi-region, log file validation on | Attackers with stolen keys like regions nobody watches. Validation gives tamper evidence. |
| VPC Flow Logs | All traffic, 1-minute aggregation, to S3 | Network evidence for the workload VPC |
| GuardDuty | Foundational + S3 data events; paid add-ons explicitly off | Catches behaviour that single API calls can't show; the bill stays flat after the trial |
| Security Hub | Findings aggregator, no compliance standards | Standards need AWS Config, which bills per configuration item |
| Athena | Partition projection, 1 GB per-query scan limit | A queryable log lake that costs $0 when idle; no crawlers |

Everything lands in one S3 log archive, which has TLS-only access, versioning, lifecycle expiry and a bucket policy scoped to exactly the CloudTrail trail and my account's flow-log delivery.

On top of that sit seven saved Athena hunting queries:
- root activity
- console logins without MFA
- AccessDenied bursts by principal (credential enumeration)
- logging tampering
- IAM persistence
- rejected inbound flows
- top outbound talkers

## Phase 4: Detection engineering

Each detection is a single JSON file containing:
- metadata, including the MITRE ATT&CK mapping
- the EventBridge event pattern
- the name of the Lambda responder that handles it

Terraform loops over the folder, so adding a detection means adding a file.

| ID | Detection | ATT&CK | Automated response |
|----|-----------|--------|--------------------|
| DL-001 | Root account used | T1078.004 | Slack alert |
| DL-002 | Logging disabled or modified | T1562.008 | Restart a stopped trail + alert |
| DL-003 | Security group opened to 0.0.0.0/0 | T1562.007 | Revoke the specific offending rules |
| DL-004 | Credentials or admin rights granted to another user | T1098.001 | Quarantine the user: deny-all, keys off, password removed |
| DL-005 | Bucket policy grants public or cross-account access | T1537 | Delete the bucket policy |
| DL-006 | GuardDuty finding, severity ≥ 4 | varies | Slack alert |

Lessons from building them:

**Some logic can't live in the event pattern.** EventBridge can match "someone called PutBucketPolicy" but not "this policy grants another account access". So DL-003, DL-004 and DL-005 match broadly and make the decision in Python. Benign events exit quietly; only real hits log a `DETECTION_FIRED` record and alert Slack.

**Auto-remediation needs a "don't shoot yourself" list.** The first version of DL-004 would have quarantined me the first time I created an access key for another user. Now there's a protected-users list (alert, never quarantine), and self-service key rotation doesn't fire at all.

**Responses should be narrow and reversible.**
- DL-003 revokes the exact rule IDs from the API response, not every open rule on the group.
- DL-004 tags and locks the user rather than deleting anything, so a false positive is a two-minute fix.
- DL-005 refuses to touch the lab's own log buckets, because deleting *that* policy would break CloudTrail delivery.

**The responders are least privilege too.** The quarantine Lambda can call `iam:AttachUserPolicy` *only* with the `AWSDenyAll` policy, enforced by an IAM condition. Even a compromised responder can't use its role to grant admin.

**Secrets stay out of state.** Terraform creates the Slack webhook parameter with a placeholder and never reads or writes the real value. The URL only exists in SSM Parameter Store and in Lambda memory.

Every responder is unit tested against sample CloudTrail events, and every rule's pattern is tested against every fixture, so each event matches its own rule and no other. That's 51 tests that run offline in under a second.

## Phase 5: Attacking it

I used [Stratus Red Team](https://stratus-red-team.cloud/) to detonate real attack techniques against the lab. A small harness (`attack-sim/validate.py`) does four things for each technique:
1. Warms up the prerequisites and detonates the attack.
2. Polls the responder log group for a `DETECTION_FIRED` record from the expected detection.
3. Records time-to-detect.
4. Cleans up.

It refuses to run if the credentials belong to any account other than the lab.

### Results

| Technique | Detection | Result | Time to detect | Automated response |
|-----------|-----------|--------|----------------|--------------------|
| Stop CloudTrail trail | DL-002 | ✅ | 4s | Trail restarted |
| Delete CloudTrail trail | DL-002 | ✅ | 2s | Alert |
| Delete VPC flow logs | DL-002 | ✅ | 2s | Alert |
| Open port 22 to the internet | DL-003 | ✅ | 9s | Rule revoked |
| Create admin IAM user | DL-004 | ✅ | 6s | User quarantined, key deactivated |
| Add console password to a user | DL-004 | ✅ | 3s | User quarantined, password removed |
| Backdoor access key on a user | DL-004 | ✅ | 3s | User quarantined, key deactivated |
| Backdoor S3 bucket policy (external account) | DL-005 | ✅ | 11s | Bucket policy deleted |
| Steal EC2 instance credentials | DL-006 | ⛔ Blocked | — | Attack failed (see below) |

Time to detect is measured from the start of detonation to the responder's log line. It covers the full path: CloudTrail → EventBridge → Lambda → remediation → Slack.

### The one that didn't fire, and why that's good

The credential-theft technique failed during detonation with `unable to parse response from instance metadata`. I dug into Stratus's source: it steals the role's credentials by running a plain `curl` against the instance metadata service, which is an IMDSv1-style request with no session token. In Phase 2 I made IMDSv2 *required* by default for every new instance in the account, and Stratus's instance doesn't override that. The metadata service refused the request and the credentials never left the box.

So the detection never got tested, because a **preventive control stopped the attack first**. That's defence in depth working as intended, and a nice example of a one-line baseline setting earning its keep.

To validate the DL-006 alerting path itself, I use a GuardDuty sample finding of the same type (`InstanceCredentialExfiltration.OutsideAWS`).

### What broke, and what I changed

The detections worked first time. The tooling around them didn't.

1. **Stratus ignored my configured region.** Every technique failed warmup on the first run. Stratus reads the region only from the `AWS_REGION` environment variable, not from `~/.aws/config` like the AWS CLI does. Worse, it logs errors to stdout, so my harness reported a bare "warmup failed". *Fix:* the harness now exports the configured region and pulls the real error from both output streams.
2. **My auto-remediation fought the red-team tool's cleanup.** Three cleanups failed, and the reason is the most interesting lesson of the project. Stratus cleans up by *reverting* its attack (revoke the rule it added, delete the password it created). My responders had already reverted those changes within seconds, so Stratus's revert hit "not found" and stopped. In one case, the user quarantine (`AWSDenyAll` attached) also blocked Stratus from deleting the IAM user it created. *Fix:* the harness now lifts any quarantine applied during the run. If Stratus's revert still fails because the change was already undone, it skips the revert and destroys only the prerequisites.

   This is a real-world tension, not just a lab quirk. Aggressive auto-remediation also destroys evidence and confuses anyone else (a pentester, another tool, a teammate) who expects the environment to stay as they left it.

### Known gaps


- **EventBridge rules are regional.** API calls in other regions are recorded by the multi-region trail but don't alert in real time. IAM and console sign-in events are global and arrive in us-east-1, which is the main reason the lab lives there. The fix is cross-region event forwarding.
- **`ModifySecurityGroupRules` bypasses DL-003.** It's another API that can open a security group.
- **DL-004 quarantines the target, not the actor.** If a stolen admin key creates a backdoor user, the backdoor is cut off but the stolen key isn't.
- **Read-only enumeration isn't alerted on.** It's covered by an Athena hunting query instead.
- **DL-005 never sees fully public policies.** The account-level S3 Block Public Access rejects them before the call succeeds, which is another layer doing its job. In practice DL-005 catches the cross-account case.


## What's next

- Close the gaps above, starting with cross-region event forwarding and `ModifySecurityGroupRules`.
- Quarantine the *actor* as well as the target in DL-004, with a protected-principal check.
- Migrate from a long-lived admin IAM user to IAM Identity Center with short-lived credentials.
- More Stratus techniques: Secrets Manager mass retrieval, CloudTrail event selectors, S3 lifecycle-based log deletion.
