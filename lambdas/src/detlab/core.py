"""Shared plumbing for every responder: AWS clients, the DETECTION_FIRED log
line that attack validation (Phase 5) looks for, and Slack alerting.

Every Lambda receives the payload built by the EventBridge input transformer:
    {"detection": {...rule metadata...}, "event": {...original event...}}
"""

import json
import logging
import os
import urllib.request
from functools import lru_cache

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_yellow_circle:",
}

_webhook_url = None


@lru_cache(maxsize=None)
def client(service):
    return boto3.client(service)


def detail(payload):
    return payload["event"].get("detail") or {}


def env_list(name):
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def principal_of(d):
    identity = d.get("userIdentity") or {}
    return identity.get("arn") or identity.get("type") or "unknown"


def record(payload, action, summary, severity=None, extra=None):
    """Log a DETECTION_FIRED line and send the Slack alert. Returns the record."""
    detection = payload["detection"]
    event = payload["event"]
    d = detail(payload)

    rec = {
        "marker": "DETECTION_FIRED",
        "detection_id": detection["id"],
        "detection": detection["name"],
        "severity": severity or detection.get("severity", "medium"),
        "event_id": d.get("eventID") or d.get("id") or event.get("id"),
        "event_time": event.get("time"),
        "principal": principal_of(d),
        "source_ip": d.get("sourceIPAddress"),
        "region": event.get("region"),
        "account": event.get("account"),
        "summary": summary,
        "action": action,
    }
    if extra:
        rec.update(extra)

    print(json.dumps(rec))
    send_slack(rec, detection)
    return rec


def format_slack(rec, detection):
    emoji = SEVERITY_EMOJI.get(rec["severity"], ":warning:")
    lines = [
        f"{emoji} *[{rec['severity'].upper()}] {rec['detection_id']} {detection.get('title', rec['detection'])}*",
        f"*What:* {rec['summary']}",
        f"*Who:* `{rec['principal']}`" + (f"  *From:* `{rec['source_ip']}`" if rec.get("source_ip") else ""),
        f"*Where:* account `{rec['account']}` / `{rec['region']}`",
        f"*Response:* {rec['action']}",
    ]
    if detection.get("attack"):
        lines.append(f"*ATT&CK:* {detection['attack']}")
    return {"text": "\n".join(lines)}


def _webhook():
    """Read the webhook from SSM once per container. An unset value isn't
    cached, so setting the parameter takes effect on the next alert."""
    global _webhook_url
    if _webhook_url is None:
        name = os.environ.get("SLACK_WEBHOOK_PARAM")
        if not name:
            return ""
        try:
            value = client("ssm").get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
        except Exception:  # noqa: BLE001 — alerting must never break the response
            log.exception("could not read Slack webhook parameter %s", name)
            return ""
        if not value.startswith("https://hooks.slack.com/"):
            return ""
        _webhook_url = value
    return _webhook_url


def send_slack(rec, detection):
    url = _webhook()
    if not url:
        log.warning("Slack webhook not configured; alert only logged")
        return
    body = json.dumps(format_slack(rec, detection)).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception:  # noqa: BLE001 — don't raise: a retry would re-run the remediation
        log.exception("Slack post failed")
