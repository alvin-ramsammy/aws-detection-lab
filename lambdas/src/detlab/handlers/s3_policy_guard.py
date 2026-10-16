"""DL-005: S3 bucket policy backdoor. EventBridge can match on the API call
but not on what the policy *means*, so the analysis happens here: flag Allow
statements for anonymous principals or principals in another account."""

import json
import re

from botocore.exceptions import ClientError

from detlab import core

# Conditions that pin an anonymous principal down to something we control.
SCOPING_KEYS = {
    "aws:sourceaccount", "aws:sourcearn", "aws:sourceowner", "aws:principalaccount",
    "aws:principalorgid", "aws:sourcevpc", "aws:sourcevpce",
}
ACCOUNT_RE = re.compile(r"(?:^|:)(\d{12})(?::|$)")


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _is_scoped(stmt):
    for operator in (stmt.get("Condition") or {}).values():
        if any(k.lower() in SCOPING_KEYS for k in operator):
            return True
    return False


def risky_grants(policy, own_account):
    if isinstance(policy, str):
        policy = json.loads(policy)
    findings = []
    for stmt in _as_list(policy.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        aws_principals = ["*"] if principal == "*" else _as_list((principal or {}).get("AWS", []))
        for p in aws_principals:
            if p == "*":
                if not _is_scoped(stmt):
                    findings.append("anonymous access (Principal *)")
                continue
            m = ACCOUNT_RE.search(p)
            if m and m.group(1) != own_account:
                findings.append(f"access for external account {m.group(1)}")
    return findings


def handler(payload, context=None):
    d = core.detail(payload)
    params = d.get("requestParameters") or {}
    bucket = params.get("bucketName")
    findings = risky_grants(params.get("bucketPolicy") or {}, d.get("recipientAccountId") or payload["event"].get("account"))
    if not findings:
        return {"status": "policy ok"}

    if bucket in core.env_list("PROTECTED_BUCKETS"):
        action = "alert only — lab log bucket, deleting its policy would break log delivery"
    else:
        try:
            core.client("s3").delete_bucket_policy(Bucket=bucket)
            action = "deleted bucket policy"
        except ClientError as e:
            action = f"FAILED to delete policy: {e.response['Error']['Code']}"

    summary = f"`{bucket}` policy grants " + "; ".join(sorted(set(findings)))
    return core.record(payload, action=action, summary=summary, extra={"bucket": bucket})
