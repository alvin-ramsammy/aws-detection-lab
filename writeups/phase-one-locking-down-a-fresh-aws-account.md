# Phase 1: Locking Down a Fresh AWS Account

*Part 1 of the [aws-detection-lab](../README.md) series — building an AWS detection and response lab from scratch, as code, and attacking it to prove the detections work.*

---

Here's what I did, why each step matters, and what I learned actually touching AWS for the first time.

## Threat model for an empty account

An account with nothing in it still has three things worth protecting: the root identity (total control), the billing relationship (a compromised account mining crypto on my card), and the credentials that will accumulate as the lab grows. Every step below maps to one of those.

## 1. Root: lock it and leave it

The root user can do anything and can't be permission-restricted, so the only safe posture is: MFA it, strip it of programmatic credentials, and stop using it.

- Enabled MFA on root via authenticator app
- Verified zero root access keys exist — root should never have programmatic credentials
- Filled in the alternate security contact
- Signed out; root gets used again only for the handful of tasks AWS reserves for it


## 2. A working identity that isn't root

Day-to-day work happens as an IAM user with its own MFA:

- Created an `Admins` group with the `AdministratorAccess` managed policy, and an admin user inside it
- Set an account alias for a readable sign-in URL
- Enabled MFA on the admin user too

Worth being honest about the tradeoff: a long-lived admin IAM user is the *lab-simple* version of this. Production orgs use IAM Identity Center with short-lived federated credentials, and a later phase will migrate to that. For a solo lab, one MFA'd admin user is an acceptable, well-understood risk.

The bigger takeaway was conceptual: IAM's primitives — users, groups, policies, and especially **roles** (temporary identities that get *assumed* rather than logged into) — are the heart of AWS security. Most real cloud breaches are IAM stories: privilege escalation, over-permissive policies, stolen credentials. The detection phases of this lab will spend a lot of time here.

## 3. Billing guardrails before any resources

Cost alarms went in before the first resource, not after the first surprise:

- A zero-spend budget that alerts the moment anything bills at all
- A monthly budget with alerts at 50/75/100%
- A CloudWatch billing alarm (these only live in us-east-1) as a second, independent tripwire

This is a security control as much as a financial one — anomalous spend is often the first visible symptom of a compromised account.

## 4. Account-wide safe defaults

Two settings that kill entire bug classes:

- Confirmed **S3 Block Public Access** is enforced account-wide — the setting that prevents the classic "public bucket" data leak
- Enabled **default EBS encryption** in my lab region

Also committed to a single region for the whole lab: less sprawl, lower cost, and no orphaned resources hiding in regions I never look at.

## 5. Touching the primitives

Then the hands-on tour — create, inspect, destroy — for the three services everything else builds on:

**S3** — created a bucket, watched it inherit the account-level public-access block, checked default encryption, then deleted it.

**EC2** — launched a `t3.micro`, and immediately hit something instructive: the default launch flow happily creates a security group allowing SSH from `0.0.0.0/0` — the entire internet. That's an insecure-by-default pattern that I'm planning for this lab to detect automatically in later phases. Terminated the instance after poking around.

**VPC** — walked the default VPC instead of creating rne: subnets, the route table with its `0.0.0.0/0` route to the internet gateway (which is precisely what makes a subnet "public"), and the two firewall layers — security groups (stateful, instance-level) versus NACLs (stateless, subnet-level). This map matters because VPC Flow Logs, coming in Phase 3, only make sense if you can read them against this topology.


## 6. Tooling and repo hygiene

- Installed the AWS CLI and Terraform; verified CLI auth with `aws sts get-caller-identity`
- Created this repo with a `.gitignore` covering `*.tfstate*`, `.terraform/`, `*.pem`, and `.env` **before any Terraform exists** — state files contain secrets in plaintext, and committing one is the classic self-inflicted breach
- The CLI currently authenticates with a long-lived access key — noted as tech debt to rotate regularly and eventually replace with Identity Center SSO

