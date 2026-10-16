from src.shared.constants import MITRE_MAPPING

known_ips = {}


def evaluate(event):
    """Detect access key usage from a new or unusual IP address."""
    detail = event.get("detail", {})
    user_identity = detail.get("userIdentity", {})

    if user_identity.get("type") != "IAMUser":
        return None

    access_key_id = user_identity.get("accessKeyId", "")
    if not access_key_id:
        return None

    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")
    event_name = detail.get("eventName", "unknown")

    if source_ip in ["AWS Internal", "amazonaws.com"]:
        return None

    if access_key_id not in known_ips:
        known_ips[access_key_id] = set()

    if source_ip in known_ips[access_key_id]:
        return None

    is_first_ever = len(known_ips[access_key_id]) == 0
    known_ips[access_key_id].add(source_ip)

    if is_first_ever:
        return None

    mitre = MITRE_MAPPING["new_ip_access_key"]
    return {
        "rule_name": "new_ip_access_key_usage",
        "severity": "MEDIUM",
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "actor": actor,
        "source_ip": source_ip,
        "event_name": event_name,
        "event_source": detail.get("eventSource", "unknown"),
        "description": f"Access key {access_key_id} used from new IP {source_ip} by {actor} (known IPs: {known_ips[access_key_id] - {source_ip}})",
        "raw_event": str(detail)
    }