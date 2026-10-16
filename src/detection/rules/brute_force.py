from datetime import datetime, timezone, timedelta
from src.shared.constants import (
    MITRE_MAPPING, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_MINUTES
)

login_failures = {}


def evaluate(event):
    """Detect brute-force login attempts from ConsoleLogin failures."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name != "ConsoleLogin":
        return None

    response = detail.get("responseElements", {})
    if response.get("ConsoleLogin") != "Failure":
        return None

    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    if actor not in login_failures:
        login_failures[actor] = []

    login_failures[actor].append(now)

    login_failures[actor] = [
        t for t in login_failures[actor] if t > window_start
    ]

    failure_count = len(login_failures[actor])

    if failure_count >= BRUTE_FORCE_THRESHOLD:
        mitre = MITRE_MAPPING["brute_force"]
        return {
            "rule_name": "brute_force_login",
            "severity": "HIGH",
            "mitre_technique_id": mitre["technique_id"],
            "mitre_technique_name": mitre["technique_name"],
            "mitre_tactic": mitre["tactic"],
            "actor": actor,
            "source_ip": source_ip,
            "event_name": event_name,
            "event_source": "signin.amazonaws.com",
            "description": f"Brute force detected: {failure_count} failed logins from {actor} ({source_ip}) in {BRUTE_FORCE_WINDOW_MINUTES} minutes",
            "raw_event": str(detail)
        }

    return None