import json

import pytest
from botocore.exceptions import ClientError

from conftest import payload
from detlab.handlers import notify, quarantine_iam_user, restore_logging, revoke_open_ingress, s3_policy_guard


def fired(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.splitlines() if "DETECTION_FIRED" in line]


# --- DL-001 / DL-006 notify ----------------------------------------------------

def test_root_login_alerts(aws, capsys):
    notify.handler(payload("DL-001-root-console-login"))
    [rec] = fired(capsys)
    assert rec["detection_id"] == "DL-001"
    assert rec["principal"].endswith(":root")
    assert rec["action"] == "alert only"


def test_guardduty_severity_mapped(aws, capsys):
    notify.handler(payload("DL-006-guardduty-cred-exfil"))
    [rec] = fired(capsys)
    assert rec["severity"] == "high"
    assert rec["finding_type"].startswith("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration")


# --- DL-002 restore logging ---------------------------------------------------

def test_stopped_trail_is_restarted(aws, capsys):
    restore_logging.handler(payload("DL-002-cloudtrail-stop"))
    aws["cloudtrail"].start_logging.assert_called_once_with(Name="arn:aws:cloudtrail:us-east-1:111122223333:trail/detlab-trail")
    assert fired(capsys)[0]["action"].startswith("restarted logging")


def test_deleted_flow_logs_alert_only(aws, capsys):
    restore_logging.handler(payload("DL-002-delete-flow-logs"))
    assert "cloudtrail" not in aws
    assert fired(capsys)[0]["action"].startswith("alert only")


def test_restart_failure_is_reported_not_raised(aws, capsys):
    aws["cloudtrail"].start_logging.side_effect = ClientError({"Error": {"Code": "TrailNotFoundException"}}, "StartLogging")
    restore_logging.handler(payload("DL-002-cloudtrail-stop"))
    assert "FAILED" in fired(capsys)[0]["action"]


# --- DL-003 revoke open ingress -----------------------------------------------

def test_world_open_rule_is_revoked(aws, capsys):
    aws["ec2"].describe_security_groups.return_value = {"SecurityGroups": [{"Tags": []}]}
    revoke_open_ingress.handler(payload("DL-003-sg-open-ssh"))
    aws["ec2"].revoke_security_group_ingress.assert_called_once_with(
        GroupId="sg-0123456789abcdef0", SecurityGroupRuleIds=["sgr-0aaa"]
    )
    [rec] = fired(capsys)
    assert "tcp/22-22 from 0.0.0.0/0" in rec["summary"]


def test_allowlisted_group_is_left_alone(aws, capsys):
    aws["ec2"].describe_security_groups.return_value = {
        "SecurityGroups": [{"Tags": [{"Key": "detlab:allow-public", "Value": "true"}]}]
    }
    revoke_open_ingress.handler(payload("DL-003-sg-open-ssh"))
    aws["ec2"].revoke_security_group_ingress.assert_not_called()
    assert "alert only" in fired(capsys)[0]["action"]


def test_private_cidr_does_not_fire(aws, capsys):
    assert revoke_open_ingress.handler(payload("DL-003-sg-private-cidr")) == {"status": "no world-open rules"}
    assert fired(capsys) == []


# --- DL-004 quarantine IAM user -----------------------------------------------

def test_key_for_other_user_quarantines(aws, capsys, monkeypatch):
    monkeypatch.setenv("PROTECTED_IAM_USERS", "lab-admin")
    iam = aws["iam"]
    iam.list_access_keys.return_value = {"AccessKeyMetadata": [{"AccessKeyId": "AKIANEWKEY", "Status": "Active"}]}
    iam.delete_login_profile.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "DeleteLoginProfile")

    quarantine_iam_user.handler(payload("DL-004-create-access-key-other-user"))

    iam.attach_user_policy.assert_called_once_with(
        UserName="stratus-red-team-backdoor-user", PolicyArn="arn:aws:iam::aws:policy/AWSDenyAll"
    )
    iam.update_access_key.assert_called_once_with(
        UserName="stratus-red-team-backdoor-user", AccessKeyId="AKIANEWKEY", Status="Inactive"
    )
    [rec] = fired(capsys)
    assert rec["action"].startswith("quarantined")


def test_self_rotation_is_benign(aws, capsys):
    assert quarantine_iam_user.handler(payload("DL-004-self-key-rotation")) == {"status": "benign"}
    assert fired(capsys) == []


def test_protected_user_alert_only(aws, capsys, monkeypatch):
    monkeypatch.setenv("PROTECTED_IAM_USERS", "stratus-red-team-admin")
    quarantine_iam_user.handler(payload("DL-004-attach-admin-policy"))
    assert "iam" not in aws
    assert fired(capsys)[0]["action"] == "alert only — protected user"


def test_non_admin_policy_is_benign():
    d = payload("DL-004-attach-admin-policy")["event"]["detail"]
    d["requestParameters"]["policyArn"] = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    assert quarantine_iam_user.assess(d) is None


@pytest.mark.parametrize(
    "doc,expected",
    [
        ({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, True),
        ({"Statement": {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}}, True),
        ({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}, False),
        ({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}, False),
        ("%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D", True),
    ],
)
def test_grants_admin(doc, expected):
    assert quarantine_iam_user.grants_admin(doc if isinstance(doc, str) else json.dumps(doc)) is expected


# --- DL-005 S3 policy guard ---------------------------------------------------

def test_external_account_policy_is_deleted(aws, capsys):
    s3_policy_guard.handler(payload("DL-005-external-account-policy"))
    aws["s3"].delete_bucket_policy.assert_called_once_with(Bucket="stratus-red-team-bucket")
    assert "external account 193672423079" in fired(capsys)[0]["summary"]


def test_service_principal_policy_is_fine(aws, capsys):
    assert s3_policy_guard.handler(payload("DL-005-service-principal-policy")) == {"status": "policy ok"}
    assert fired(capsys) == []


def test_protected_bucket_alert_only(aws, capsys, monkeypatch):
    monkeypatch.setenv("PROTECTED_BUCKETS", "stratus-red-team-bucket")
    s3_policy_guard.handler(payload("DL-005-external-account-policy"))
    assert "s3" not in aws
    assert "alert only" in fired(capsys)[0]["action"]


@pytest.mark.parametrize(
    "stmt,risky",
    [
        ({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}, True),
        ({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "*",
          "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}}, False),
        ({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:role/x"}, "Action": "s3:*", "Resource": "*"}, False),
        ({"Effect": "Allow", "Principal": {"AWS": ["999988887777"]}, "Action": "s3:*", "Resource": "*"}, True),
        ({"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}, False),
    ],
)
def test_risky_grants(stmt, risky):
    assert bool(s3_policy_guard.risky_grants({"Statement": [stmt]}, "111122223333")) is risky


# --- Slack formatting ---------------------------------------------------------

def test_slack_message_has_the_essentials(aws, capsys):
    from detlab import core

    p = payload("DL-003-sg-open-ssh")
    aws["ec2"].describe_security_groups.return_value = {"SecurityGroups": [{"Tags": []}]}
    [rec] = revoke_open_ingress.handler(p)
    text = core.format_slack(rec, p["detection"])["text"]
    for needle in ("DL-003", "HIGH", "203.0.113.10", "revoked 1 rule", "T1562.007"):
        assert needle in text
