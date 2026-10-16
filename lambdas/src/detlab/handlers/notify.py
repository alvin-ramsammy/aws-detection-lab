"""Alert-only responder: root usage (DL-001) and GuardDuty findings (DL-006)."""

from detlab import core


def guardduty_severity(score):
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def handler(payload, context=None):
    event = payload["event"]
    d = core.detail(payload)

    if event.get("source") == "aws.guardduty":
        score = float(d.get("severity", 0))
        summary = f"{d.get('type')}: {d.get('title')}"
        return core.record(
            payload,
            action="alert only",
            summary=summary,
            severity=guardduty_severity(score),
            extra={"finding_type": d.get("type"), "finding_id": d.get("id"), "guardduty_severity": score},
        )

    summary = f"{d.get('eventName')} by {core.principal_of(d)}"
    return core.record(payload, action="alert only", summary=summary)
