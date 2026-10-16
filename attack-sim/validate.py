#!/usr/bin/env python3
"""Phase 5: detonate Stratus Red Team techniques against the lab and check
that the matching detection fired.

For each technique: warm up -> detonate -> poll the responder log group for a
DETECTION_FIRED line from the expected detection -> clean up. Results go to
attack-sim/results/<date>.md, ready to paste into the README.

Requires: stratus (https://github.com/DataDog/stratus-red-team) on PATH,
boto3, and AWS credentials for the lab account.

    python3 attack-sim/validate.py --account-id 123456789012
    python3 attack-sim/validate.py --account-id 123456789012 --only aws.defense-evasion.cloudtrail-stop
"""

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import time

import boto3

LOG_GROUP = "/detlab/responders"
STRATUS = os.environ.get("STRATUS_BIN", "stratus")
RESULTS_DIR = pathlib.Path(__file__).parent / "results"
STRATUS_HOME = pathlib.Path.home() / ".stratus-red-team"

# technique -> (expected detection, timeout in seconds)
TECHNIQUES = {
    "aws.defense-evasion.cloudtrail-stop": ("DL-002", 600),
    "aws.defense-evasion.cloudtrail-delete": ("DL-002", 600),
    "aws.defense-evasion.vpc-remove-flow-logs": ("DL-002", 600),
    "aws.exfiltration.ec2-security-group-open-port-22-ingress": ("DL-003", 600),
    "aws.persistence.iam-create-admin-user": ("DL-004", 600),
    "aws.persistence.iam-create-user-login-profile": ("DL-004", 600),
    "aws.persistence.iam-backdoor-user": ("DL-004", 600),
    "aws.exfiltration.s3-backdoor-bucket-policy": ("DL-005", 600),
    # GuardDuty needs time to notice credentials used outside AWS.
    "aws.credential-access.ec2-steal-instance-credentials": ("DL-006", 2400),
}


def stratus(*args):
    print(f"  $ stratus {' '.join(args)}", flush=True)
    return subprocess.run([STRATUS, *args], capture_output=True, text=True)


def last_error(proc):
    """Stratus logs to stdout, so look at both streams for the reason."""
    lines = [l.strip() for l in (proc.stderr + "\n" + proc.stdout).splitlines() if l.strip()]
    for line in reversed(lines):
        if any(w in line.lower() for w in ("error", "fail", "not authenticated", "denied")):
            return line[:200]
    return lines[-1][:200] if lines else "no output"


def find_detection(logs, log_group, detection_id, since):
    """Return the first DETECTION_FIRED record for detection_id after `since`."""
    pages = logs.get_paginator("filter_log_events").paginate(
        logGroupName=log_group,
        startTime=int(since.timestamp() * 1000),
        filterPattern=f'"DETECTION_FIRED" "{detection_id}"',
    )
    for e in (e for page in pages for e in page.get("events", [])):
        try:
            rec = json.loads(e["message"][e["message"].index("{"):])
        except ValueError:
            continue
        if rec.get("detection_id") == detection_id:
            rec["_logged_at"] = dt.datetime.fromtimestamp(e["timestamp"] / 1000, dt.timezone.utc)
            return rec
    return None


def release_quarantine(iam, since):
    """DL-004 attaches AWSDenyAll to the users Stratus creates, which blocks
    Stratus from deleting them during cleanup. Undo that, but only for users
    quarantined during this run (the detlab:quarantined tag holds the time)."""
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            tags = {t["Key"]: t["Value"] for t in iam.list_user_tags(UserName=name)["Tags"]}
            stamp = tags.get("detlab:quarantined")
            if not stamp or dt.datetime.fromisoformat(stamp) < since:
                continue
            try:
                iam.detach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/AWSDenyAll")
            except iam.exceptions.NoSuchEntityException:
                pass
            iam.untag_user(UserName=name, TagKeys=["detlab:quarantined"])
            print(f"  released quarantine on {name}")


def cleanup(technique):
    """Run stratus cleanup. If it fails because a responder already reverted
    the detonation (e.g. the SG rule is already gone), Stratus's own revert
    step errors out. In that case mark the technique WARM so cleanup skips the
    revert and just destroys the prerequisites."""
    clean = stratus("cleanup", technique)
    if clean.returncode == 0:
        return ""
    state = STRATUS_HOME / technique / ".state"
    if state.exists() and state.read_text().strip() == "DETONATED":
        state.write_text("WARM")
        retry = stratus("cleanup", technique)
        if retry.returncode == 0:
            return "Stratus revert skipped (responder had already reverted it)"
    return "cleanup failed, run `stratus cleanup` manually: " + last_error(clean)


def run(technique, detection_id, timeout, logs, iam, log_group):
    result = {"technique": technique, "expected": detection_id, "fired": False, "ttd": None, "action": "", "notes": ""}

    warm = stratus("warmup", technique)
    if warm.returncode != 0:
        result["notes"] = "warmup failed: " + last_error(warm)
        return result

    started = dt.datetime.now(dt.timezone.utc)
    try:
        det = stratus("detonate", technique)
        if det.returncode != 0:
            result["notes"] = "detonation failed: " + last_error(det)
            return result

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rec = find_detection(logs, log_group, detection_id, started)
            if rec:
                result.update(fired=True, ttd=(rec["_logged_at"] - started).total_seconds(), action=rec.get("action", ""))
                break
            time.sleep(15)
        if not result["fired"]:
            result["notes"] = f"no {detection_id} within {timeout}s"
    finally:
        release_quarantine(iam, started)
        note = cleanup(technique)
        if note:
            result["notes"] = "; ".join(n for n in (result["notes"], note) if n)
    return result


def write_report(results):
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"{dt.date.today().isoformat()}.md"
    lines = [
        f"# Attack validation run — {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
        "",
        "| Technique | Expected | Fired | Time to detect | Response | Notes |",
        "|-----------|----------|-------|----------------|----------|-------|",
    ]
    for r in results:
        ttd = f"{r['ttd']:.0f}s" if r["ttd"] is not None else "—"
        cells = [f"`{r['technique']}`", r["expected"], "✅" if r["fired"] else "❌", ttd, r["action"], r["notes"]]
        lines.append("| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |")
    path.write_text("\n".join(lines) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--account-id", required=True, help="The lab account. The script refuses to run anywhere else.")
    ap.add_argument("--log-group", default=LOG_GROUP, help="Responder log group (terraform output responder_log_group).")
    ap.add_argument("--only", action="append", choices=sorted(TECHNIQUES), help="Run only these techniques.")
    args = ap.parse_args()

    # Stratus only reads the region from the environment, not ~/.aws/config.
    region = os.environ.get("AWS_REGION") or boto3.session.Session().region_name
    if not region:
        sys.exit("No AWS region configured. Run `aws configure` or export AWS_REGION.")
    os.environ["AWS_REGION"] = region

    actual = boto3.client("sts").get_caller_identity()["Account"]
    if actual != args.account_id:
        sys.exit(f"Refusing to run: credentials are for account {actual}, not {args.account_id}.")

    logs, iam = boto3.client("logs"), boto3.client("iam")
    results = []
    for technique in args.only or TECHNIQUES:
        detection_id, timeout = TECHNIQUES[technique]
        print(f"\n== {technique} (expect {detection_id}) ==", flush=True)
        r = run(technique, detection_id, timeout, logs, iam, args.log_group)
        print(f"  -> {'FIRED' if r['fired'] else 'MISSED'} {r['ttd'] or ''} {r['notes']}")
        results.append(r)

    print(f"\nReport: {write_report(results)}")
    sys.exit(0 if all(r["fired"] for r in results) else 1)


if __name__ == "__main__":
    main()
