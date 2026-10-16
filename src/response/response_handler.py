import json
import logging
from src.response.iam_key_revoke import revoke_access_key
from src.response.ec2_isolate import isolate_instance, find_instance_by_private_ip

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RESPONSE_MAP = {
    "brute_force_login": ["iam_key_revoke"],
    "impossible_travel": ["iam_key_revoke"],
    "iam_privilege_escalation": ["iam_key_revoke"],
    "new_ip_access_key_usage": ["iam_key_revoke"],
    "root_account_usage": [],
    "s3_enumeration": ["iam_key_revoke"],
    "security_group_modification": [],
    "network_scanning": ["ec2_isolate"]
}


def handle_response(alert):
    """Determine and execute the appropriate response for an alert."""
    rule_name = alert.get("rule_name", "")
    actions = RESPONSE_MAP.get(rule_name, [])
    results = []

    if not actions:
        logger.info(f"No automated response for rule: {rule_name}. Alert only.")
        return {
            "alert_id": alert.get("alert_id", ""),
            "actions_taken": [],
            "message": "Alert only — no automated response configured"
        }

    for action in actions:
        if action == "iam_key_revoke":
            result = revoke_access_key(alert)
            results.append(result)

        elif action == "ec2_isolate":
            source_ip = alert.get("source_ip", "")
            instance_id = alert.get("instance_id") or find_instance_by_private_ip(source_ip)
            if instance_id:
                result = isolate_instance(alert, instance_id)
                results.append(result)
            else:
                logger.warning(f"No EC2 instance in this account owns {source_ip}; skipping ec2_isolate")

    logger.info(f"Response complete for alert {alert.get('alert_id', '')}: {results}")

    return {
        "alert_id": alert.get("alert_id", ""),
        "actions_taken": results
    }