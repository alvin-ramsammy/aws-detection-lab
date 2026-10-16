"""DL-004: IAM persistence. Quarantines the *target* user of a suspicious IAM
change: attach AWSDenyAll, deactivate access keys, remove console password."""

import json
import urllib.parse
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from detlab import core

DENY_ALL = "arn:aws:iam::aws:policy/AWSDenyAll"
ADMIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}
CREDENTIAL_EVENTS = {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"}


def _as_list(v):
    return v if isinstance(v, list) else [v]


def grants_admin(document):
    if isinstance(document, str):
        if document.startswith("%7B"):
            document = urllib.parse.unquote(document)
        document = json.loads(document)
    for stmt in _as_list(document.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action", []))
        resources = _as_list(stmt.get("Resource", []))
        if "*" in resources and any(a in ("*", "iam:*") for a in actions):
            return True
    return False


def assess(d):
    """Return (target_user, reason) if this event should trigger, else None."""
    name = d.get("eventName")
    params = d.get("requestParameters") or {}
    target = params.get("userName")
    actor = (d.get("userIdentity") or {}).get("userName")

    if name in CREDENTIAL_EVENTS:
        # No userName means the caller acted on itself (routine key rotation).
        if not target or target == actor:
            return None
        return target, f"{name} for user `{target}`"
    if name == "AttachUserPolicy" and params.get("policyArn") in ADMIN_POLICIES:
        return target, f"`{params['policyArn'].split('/')[-1]}` attached to user `{target}`"
    if name == "PutUserPolicy" and grants_admin(params.get("policyDocument", "{}")):
        return target, f"admin inline policy `{params.get('policyName')}` put on user `{target}`"
    return None


def quarantine(user):
    iam = core.client("iam")
    steps = []
    iam.attach_user_policy(UserName=user, PolicyArn=DENY_ALL)
    steps.append("attached AWSDenyAll")
    for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        if key["Status"] == "Active":
            iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            steps.append(f"deactivated key {key['AccessKeyId'][:8]}…")
    try:
        iam.delete_login_profile(UserName=user)
        steps.append("removed console password")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.tag_user(UserName=user, Tags=[{"Key": "detlab:quarantined", "Value": datetime.now(timezone.utc).isoformat()}])
    return steps


def handler(payload, context=None):
    d = core.detail(payload)
    verdict = assess(d)
    if not verdict:
        return {"status": "benign"}
    target, reason = verdict

    if target in core.env_list("PROTECTED_IAM_USERS"):
        action = "alert only — protected user"
    else:
        try:
            action = "quarantined: " + ", ".join(quarantine(target))
        except ClientError as e:
            action = f"FAILED to quarantine: {e.response['Error']['Code']}"

    return core.record(payload, action=action, summary=f"{reason} by {core.principal_of(d)}", extra={"target_user": target})
