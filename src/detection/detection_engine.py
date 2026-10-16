import json
import logging
from src.detection.rules import (
    brute_force,
    root_account_usage,
    iam_privilege_escalation,
    s3_enumeration,
    security_group_modification,
    impossible_travel,
    new_ip_access_key
)
from src.shared.db_helpers import store_alert, store_actor_history
from src.shared.constants import SNS_TOPIC_ARN

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client("sns", region_name="us-east-2")

RULES = [
    brute_force,
    root_account_usage,
    iam_privilege_escalation,
    s3_enumeration,
    security_group_modification,
    impossible_travel,
    new_ip_access_key
]


def lambda_handler(event, context):
    """Main Lambda handler — receives CloudTrail events from EventBridge."""
    logger.info(f"Received event: {json.dumps(event)}")

    alerts = []

    for rule in RULES:
        try:
            result = rule.evaluate(event)
            if result:
                alert = store_alert(result)
                alerts.append(alert)

                actor_id = result.get("actor", "unknown")
                store_actor_history(actor_id, alert)

                source_ip = result.get("source_ip", "unknown")
                if source_ip != actor_id and source_ip != "unknown":
                    store_actor_history(source_ip, alert)

                send_sns_alert(alert)

                logger.info(f"ALERT: {alert['rule_name']} - {alert['description']}")
        except Exception as e:
            logger.error(f"Error in rule {rule.__name__}: {str(e)}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": f"Processed event. Generated {len(alerts)} alert(s).",
            "alerts": [a["alert_id"] for a in alerts]
        })
    }


def send_sns_alert(alert):
    """Send alert notification via SNS."""
    subject = f"[CloudSentinel] {alert['severity']} - {alert['rule_name']}"
    message = (
        f"Rule: {alert['rule_name']}\n"
        f"Severity: {alert['severity']}\n"
        f"MITRE ATT&CK: {alert['mitre_technique_id']} - {alert['mitre_technique_name']}\n"
        f"Tactic: {alert['mitre_tactic']}\n"
        f"Actor: {alert['actor']}\n"
        f"Source IP: {alert['source_ip']}\n"
        f"Event: {alert['event_name']}\n"
        f"Description: {alert['description']}\n"
        f"Time: {alert['timestamp']}\n"
        f"Alert ID: {alert['alert_id']}"
    )

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message
        )
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {str(e)}")