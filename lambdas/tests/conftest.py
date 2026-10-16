import json
import pathlib
import sys
from unittest.mock import MagicMock

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambdas" / "src"))

from detlab import core  # noqa: E402

RULES = {json.loads(p.read_text())["id"]: json.loads(p.read_text()) for p in (ROOT / "detections" / "rules").glob("*.json")}
FIXTURES = ROOT / "detections" / "fixtures"


def load_event(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def payload(name):
    """Build the payload exactly as the EventBridge input transformer does."""
    detection_id = "-".join(name.split("-")[:2])
    meta = {k: v for k, v in RULES[detection_id].items() if k != "event_pattern"}
    return {"detection": meta, "event": load_event(name)}


class Clients(dict):
    """service name -> MagicMock, created on first use (by the handler or the test)."""

    def __missing__(self, service):
        self[service] = MagicMock(name=service)
        return self[service]


@pytest.fixture
def aws(monkeypatch):
    """Replace every boto3 client with a per-service MagicMock and disable Slack."""
    clients = Clients()
    monkeypatch.setattr(core, "client", clients.__getitem__)
    monkeypatch.setattr(core, "_webhook_url", "")
    return clients
