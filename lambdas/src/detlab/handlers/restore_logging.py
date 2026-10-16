"""DL-002: logging tampering. Restarts a stopped CloudTrail trail; everything
else (deleted trails, flow logs, detectors) is alert-only because recreating
them belongs to Terraform, not to a Lambda."""

from botocore.exceptions import ClientError

from detlab import core


def handler(payload, context=None):
    d = core.detail(payload)
    name = d.get("eventName")
    params = d.get("requestParameters") or {}

    if name == "StopLogging":
        trail = params.get("name")
        try:
            core.client("cloudtrail").start_logging(Name=trail)
            action = f"restarted logging on trail `{trail}`"
        except ClientError as e:
            action = f"FAILED to restart trail `{trail}`: {e.response['Error']['Code']}"
    else:
        action = "alert only — restore with `terraform apply`"

    target = params.get("name") or params.get("detectorId") or ",".join(params.get("flowLogIds") or []) or ""
    summary = f"{name} {target}".strip() + f" by {core.principal_of(d)}"
    return core.record(payload, action=action, summary=summary)
