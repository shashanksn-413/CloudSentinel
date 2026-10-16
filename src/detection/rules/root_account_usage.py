from datetime import datetime, timezone
from src.shared.constants import MITRE_MAPPING


def evaluate(event):
    """Detect any usage of the root account."""
    detail = event.get("detail", {})
    user_identity = detail.get("userIdentity", {})

    if user_identity.get("type") != "Root":
        return None

    invoked_by = detail.get("userIdentity", {}).get("invokedBy", "")
    if invoked_by:
        return None

    event_name = detail.get("eventName", "unknown")
    source_ip = detail.get("sourceIPAddress", "unknown")

    mitre = MITRE_MAPPING["root_account_usage"]
    return {
        "rule_name": "root_account_usage",
        "severity": "CRITICAL",
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "actor": "root",
        "source_ip": source_ip,
        "event_name": event_name,
        "event_source": detail.get("eventSource", "unknown"),
        "description": f"Root account activity detected: {event_name} from {source_ip}",
        "raw_event": str(detail)
    }