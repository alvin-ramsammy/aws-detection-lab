# aws-detection-lab

A Terraform-built AWS detection and response lab. I stand up a realistic environment as code, wire it with full security telemetry, run simulated attacks against it, and verify that every detection fires and every automated response works.

> **Status: Phase 1 — account foundations.** This is a build-in-public project; each phase gets a writeup as it lands. Follow along below.

## Why this exists

Most cloud security learning stops at "enable GuardDuty." This lab goes end to end: build → monitor → attack → detect → respond, with every step reproducible from code. The goal is to practice the actual job of a cloud security / detection engineer — and to prove it publicly.

## Architecture

<!-- TODO (Phase 3): architecture diagram goes here. Draw.io or Mermaid.
     Show: VPC + workload → CloudTrail / VPC Flow Logs / GuardDuty →
     Security Hub → EventBridge → Lambda responders → Slack alerting.
     Sanitize any account IDs before committing screenshots. -->

*Diagram coming with Phase 3 (telemetry pipeline).*

## Phases

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Account hardening: root lockdown, IAM baseline, billing guardrails, S3/EBS defaults | 🔨 In progress |
| 2 | Rebuild everything as Terraform — reproducible, destroyable | ⬜ Planned |
| 3 | Telemetry: CloudTrail, VPC Flow Logs, GuardDuty, Security Hub, Athena | ⬜ Planned |
| 4 | Detection engineering: EventBridge rules → Lambda auto-remediation | ⬜ Planned |
| 5 | Attack simulation: Stratus Red Team / CloudGoat, validate detections | ⬜ Planned |
| 6 | Writeups and packaging | ⬜ Planned |

## Detections

<!-- TODO (Phase 4+): one row per detection as you build them. Example row shown. -->

| Detection | ATT&CK technique | Telemetry source | Automated response |
|-----------|------------------|------------------|--------------------|
| *Example: IAM access key used from new geo* | *T1078 — Valid Accounts* | *CloudTrail via GuardDuty* | *Lambda quarantines key, alerts Slack* |

## Attack validation

<!-- TODO (Phase 5): for each simulated technique — what I ran, what fired,
     time-to-detect, what missed, and what I changed as a result.
     Link the full writeup for each. -->

*Populated during Phase 5 — each attack gets: technique run, detection result, and the fix for anything that missed.*

## Repo layout

```
terraform/          # All infrastructure as code
  modules/          # Reusable modules (logging, detection, response)
  envs/lab/         # The lab environment
detections/         # Detection rules as code (EventBridge patterns, queries)
lambdas/            # Auto-remediation functions (Python)
writeups/           # Phase writeups and attack narratives
```

## Running it yourself

```bash
# Prereqs: AWS account, Terraform >= 1.7, AWS CLI configured
cd terraform/envs/lab
terraform init
terraform plan
terraform apply

# Tear down when done — this lab is designed to be destroyed between sessions
terraform destroy
```

**Cost notes:** single region, single AZ, Athena instead of always-on OpenSearch, `terraform destroy` between sessions. Designed to run on a small credit budget without surprises.

## Security hygiene in this repo

- No Terraform state committed (`.gitignore` covers `*.tfstate*` — state files contain secrets)
- `gitleaks` runs pre-commit; account IDs sanitized in all screenshots and logs
- Attacks are run **only** against this environment, which I own

## Writeups

<!-- TODO: link each writeup as published -->
- *Phase 1: Locking down a fresh AWS account — coming soon*
