#!/usr/bin/env python3
"""Check every fixture against every rule using the real EventBridge
TestEventPattern API (no resources are created). The offline tests in
lambdas/tests use a local matcher; this confirms AWS agrees with it."""

import json
import pathlib
import sys

import boto3

HERE = pathlib.Path(__file__).parent
rules = {json.loads(p.read_text())["id"]: json.loads(p.read_text()) for p in sorted((HERE / "rules").glob("*.json"))}
events = boto3.client("events")
failures = 0

for fixture in sorted((HERE / "fixtures").glob("*.json")):
    expected = "-".join(fixture.stem.split("-")[:2])
    event = fixture.read_text()
    matched = [i for i, r in rules.items()
               if events.test_event_pattern(EventPattern=json.dumps(r["event_pattern"]), Event=event)["Result"]]
    ok = matched == [expected]
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {fixture.stem}: matched {matched or 'nothing'}")

sys.exit(1 if failures else 0)
