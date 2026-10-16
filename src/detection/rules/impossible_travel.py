import math
from datetime import datetime, timezone
from src.shared.constants import MITRE_MAPPING

last_login = {}


MAX_TRAVEL_SPEED_KPH = 900


def haversine_km(lat1, lon1, lat2, lon2):
    """Calculate distance between two coordinates in kilometers."""
    R = 6371
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def evaluate(event):
    """Detect impossible travel — same user logging in from distant IPs in a short window."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name != "ConsoleLogin":
        return None

    response = detail.get("responseElements", {})
    if response.get("ConsoleLogin") != "Success":
        return None

    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")
    event_time_str = detail.get("eventTime", "")

    try:
        event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        event_time = datetime.now(timezone.utc)

    if actor in last_login:
        prev = last_login[actor]
        prev_ip = prev["source_ip"]
        prev_time = prev["event_time"]

        if prev_ip != source_ip:
            time_diff_hours = (event_time - prev_time).total_seconds() / 3600

            if time_diff_hours < 1:
                mitre = MITRE_MAPPING["impossible_travel"]
                last_login[actor] = {
                    "source_ip": source_ip,
                    "event_time": event_time
                }
                return {
                    "rule_name": "impossible_travel",
                    "severity": "HIGH",
                    "mitre_technique_id": mitre["technique_id"],
                    "mitre_technique_name": mitre["technique_name"],
                    "mitre_tactic": mitre["tactic"],
                    "actor": actor,
                    "source_ip": source_ip,
                    "event_name": event_name,
                    "event_source": "signin.amazonaws.com",
                    "description": f"Impossible travel: {actor} logged in from {prev_ip} then {source_ip} within {time_diff_hours:.2f} hours",
                    "raw_event": str(detail)
                }

    last_login[actor] = {
        "source_ip": source_ip,
        "event_time": event_time
    }

    return None