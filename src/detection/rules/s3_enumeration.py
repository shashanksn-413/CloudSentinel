from datetime import datetime, timezone, timedelta
from src.shared.constants import (
    MITRE_MAPPING, S3_ENUM_THRESHOLD, S3_ENUM_WINDOW_MINUTES
)

s3_list_tracker = {}

S3_ENUM_ACTIONS = [
    "ListBuckets",
    "ListObjects",
    "ListObjectsV2",
    "GetBucketAcl",
    "GetBucketPolicy",
    "GetBucketLocation",
    "HeadBucket"
]


def evaluate(event):
    """Detect S3 bucket enumeration from rapid list/get calls."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name not in S3_ENUM_ACTIONS:
        return None

    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=S3_ENUM_WINDOW_MINUTES)
    tracker_key = f"{actor}:{source_ip}"

    if tracker_key not in s3_list_tracker:
        s3_list_tracker[tracker_key] = []

    s3_list_tracker[tracker_key].append(now)

    s3_list_tracker[tracker_key] = [
        t for t in s3_list_tracker[tracker_key] if t > window_start
    ]

    call_count = len(s3_list_tracker[tracker_key])

    if call_count >= S3_ENUM_THRESHOLD:
        mitre = MITRE_MAPPING["s3_enumeration"]
        return {
            "rule_name": "s3_enumeration",
            "severity": "MEDIUM",
            "mitre_technique_id": mitre["technique_id"],
            "mitre_technique_name": mitre["technique_name"],
            "mitre_tactic": mitre["tactic"],
            "actor": actor,
            "source_ip": source_ip,
            "event_name": event_name,
            "event_source": "s3.amazonaws.com",
            "description": f"S3 enumeration detected: {call_count} list/get calls from {actor} ({source_ip}) in {S3_ENUM_WINDOW_MINUTES} minutes",
            "raw_event": str(detail)
        }

    return None