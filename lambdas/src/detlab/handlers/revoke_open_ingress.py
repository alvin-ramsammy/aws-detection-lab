"""DL-003: security group opened to the internet. Revokes exactly the rules
that allow 0.0.0.0/0 or ::/0, using the rule IDs from the API response."""

from collections import defaultdict

from botocore.exceptions import ClientError

from detlab import core

ALLOW_TAG = "detlab:allow-public"
WORLD = {"0.0.0.0/0", "::/0"}


def open_rules(d):
    """Return {group_id: [rule, ...]} for rules open to the whole internet."""
    items = ((d.get("responseElements") or {}).get("securityGroupRuleSet") or {}).get("items") or []
    found = defaultdict(list)
    for rule in items:
        if rule.get("cidrIpv4") in WORLD or rule.get("cidrIpv6") in WORLD:
            found[rule["groupId"]].append(rule)
    return dict(found)


def describe_rule(rule):
    proto = rule.get("ipProtocol")
    ports = "all ports" if proto == "-1" else f"{proto}/{rule.get('fromPort')}-{rule.get('toPort')}"
    return f"{ports} from {rule.get('cidrIpv4') or rule.get('cidrIpv6')}"


def is_allowlisted(group_id):
    groups = core.client("ec2").describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    tags = {t["Key"]: t["Value"] for t in (groups[0].get("Tags") or [])} if groups else {}
    return tags.get(ALLOW_TAG) == "true"


def handler(payload, context=None):
    d = core.detail(payload)
    groups = open_rules(d)
    if not groups:
        return {"status": "no world-open rules"}

    results = []
    for group_id, rules in groups.items():
        desc = ", ".join(describe_rule(r) for r in rules)
        summary = f"`{group_id}` now allows {desc}"
        try:
            if is_allowlisted(group_id):
                action = f"alert only — group tagged `{ALLOW_TAG}=true`"
            else:
                core.client("ec2").revoke_security_group_ingress(
                    GroupId=group_id,
                    SecurityGroupRuleIds=[r["securityGroupRuleId"] for r in rules],
                )
                action = f"revoked {len(rules)} rule(s)"
        except ClientError as e:
            action = f"FAILED to revoke: {e.response['Error']['Code']}"
        results.append(core.record(payload, action=action, summary=summary, extra={"group_id": group_id}))
    return results
