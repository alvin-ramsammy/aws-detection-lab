import pytest

from conftest import FIXTURES, RULES, load_event
from pattern_match import matches

FIXTURE_NAMES = sorted(p.stem for p in FIXTURES.glob("*.json"))


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_matches_its_own_rule(name):
    detection_id = "-".join(name.split("-")[:2])
    assert matches(RULES[detection_id]["event_pattern"], load_event(name))


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_matches_no_other_rule(name):
    detection_id = "-".join(name.split("-")[:2])
    others = [i for i, r in RULES.items() if i != detection_id and matches(r["event_pattern"], load_event(name))]
    assert others == []


def test_failed_calls_do_not_match():
    event = load_event("DL-002-cloudtrail-stop")
    event["detail"]["errorCode"] = "AccessDenied"
    assert not matches(RULES["DL-002"]["event_pattern"], event)


def test_low_severity_guardduty_does_not_match():
    event = load_event("DL-006-guardduty-cred-exfil")
    event["detail"]["severity"] = 2
    assert not matches(RULES["DL-006"]["event_pattern"], event)


def test_every_rule_has_a_fixture():
    covered = {"-".join(n.split("-")[:2]) for n in FIXTURE_NAMES}
    assert covered == set(RULES)
