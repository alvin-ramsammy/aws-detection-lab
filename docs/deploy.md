# Deploy runbook

Two Terraform roots:

| Root | What | Lifecycle |
|------|------|-----------|
| `terraform/envs/account` | Phase 1 hardening as code: S3 public access block, default EBS encryption, IMDSv2 default, password policy, budgets, billing alarm, Slack webhook parameter | Apply once, leave it in place |
| `terraform/envs/lab` | Workload VPC + instance, CloudTrail, Flow Logs, GuardDuty, Security Hub, Athena, detections, responders | Apply at the start of a session, destroy at the end |

## 1. Configure the CLI

```bash
aws configure            # new access key for your admin IAM user, region us-east-1
aws sts get-caller-identity
```

## 2. Account baseline (once)

Phase 1 created two budgets and a billing alarm by hand. Terraform makes its own (`detlab-*`), so delete the console-made ones afterwards to avoid duplicate emails.

```bash
cp terraform/envs/account/terraform.tfvars.example terraform/envs/account/terraform.tfvars
# edit: account_id, alert_email
make account
```


## 3. Slack webhook (once)

```bash
make set-slack-webhook
```

You're prompted for the URL with input hidden. It's stored as an encrypted SSM parameter and never touches Terraform state, git or your shell history.

## 4. Deploy the lab (each session)

```bash
cp terraform/envs/lab/terraform.tfvars.example terraform/envs/lab/terraform.tfvars
# edit: account_id, protected_iam_users = ["<your admin user>"]
make lab-plan
make lab-apply
```

If GuardDuty or Security Hub were ever turned on by hand in this account, apply fails with "already exists". Import them, for example
`terraform import 'module.logging.aws_guardduty_detector.this' <detector-id>`.

## 5. Smoke tests

```bash
make smoke-test   # GuardDuty sample finding → DL-006 alert in Slack within ~1 minute
```

Manual check for DL-003: in the console, add an inbound rule `SSH 0.0.0.0/0` to the `detlab-workload` security group. Within about a minute the rule should disappear and Slack should say why.

## 6. Attack validation (Phase 5)

Install [Stratus Red Team](https://stratus-red-team.cloud/) (`go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest`), then run the command below. The first run creates a `.venv` with boto3; the lab from step 4 must be deployed.

```bash
make attack ACCOUNT_ID=<your account id>
```

It refuses to run if your credentials point at a different account. Results land in `attack-sim/results/<date>.md`. The GuardDuty technique can take up to 40 minutes.

DL-001 (root usage) isn't in Stratus: test it by signing in as root once and watching Slack.

## 7. Tear down

```bash
make lab-destroy
```

Expect a few DL-002 alerts while the trail, flow logs and detector are deleted, since the rules can still be live for a moment. That's the detection doing its job.

The account baseline and Slack parameter stay.

## Cost

| Item | Rough cost |
|------|-----------|
| t3.micro + 8 GB gp3 | ~$0.01/hour (free tier eligible) |
| CloudTrail management events (first trail) | free; S3 storage pennies |
| GuardDuty | 30-day free trial, then a few $/month at lab volume |
| Security Hub | 30-day free trial; with no standards enabled, findings ingestion only |
| Lambda, EventBridge, SSM | free tier |
| Athena | $5/TB scanned; capped at 1 GB/query by the workgroup |
| Billing alarm | $0.10/month |

