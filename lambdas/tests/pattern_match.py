"""A small offline implementation of the EventBridge pattern subset this repo
uses (literal lists, exists, numeric). It lets the tests prove each fixture
matches its rule without AWS credentials. `make test-patterns` checks the same
thing against the real EventBridge TestEventPattern API."""


def _match_value(rules, value):
    values = value if isinstance(value, list) else [value]
    for rule in rules:
        if isinstance(rule, dict):
            if "exists" in rule:
                if (value is not None) == rule["exists"]:
                    return True
            elif "numeric" in rule:
                op, bound = rule["numeric"]
                ops = {">=": float.__ge__, ">": float.__gt__, "<=": float.__le__, "<": float.__lt__, "=": float.__eq__}
                if any(isinstance(v, (int, float)) and ops[op](float(v), float(bound)) for v in values):
                    return True
            else:
                raise NotImplementedError(rule)
        elif rule in values:
            return True
    return False


def matches(pattern, event):
    for key, rule in pattern.items():
        value = event.get(key) if isinstance(event, dict) else None
        if isinstance(rule, dict):
            if isinstance(value, list):
                if not any(isinstance(v, dict) and matches(rule, v) for v in value):
                    return False
            elif not matches(rule, value if isinstance(value, dict) else {}):
                return False
        elif not _match_value(rule, value):
            return False
    return True
