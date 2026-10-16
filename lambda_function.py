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
from src.triage.ai_triage import triage_alert
from src.response.response_handler import handle_response
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
    """Main Lambda entry point — orchestrates detection, triage, and response."""
    logger.info(f"CloudSentinel received event: {json.dumps(event)}")

    results = []

    for rule in RULES:
        try:
            result = rule.evaluate(event)
            if result:
                alert = store_alert(result)
                logger.info(f"ALERT: {alert['rule_name']} - {alert['description']}")

                actor_id = result.get("actor", "unknown")
                store_actor_history(actor_id, alert)
                source_ip = result.get("source_ip", "unknown")
                if source_ip != actor_id and source_ip != "unknown":
                    store_actor_history(source_ip, alert)

                try:
                    triage_result = triage_alert(alert)
                    alert["triage_output"] = json.dumps(triage_result)
                    logger.info(f"TRIAGE: {triage_result}")
                except Exception as e:
                    logger.error(f"Triage failed: {str(e)}")
                    triage_result = {"severity_score": 3, "recommended_action": "monitor"}
                    alert["triage_output"] = json.dumps(triage_result)

                response_result = None
                if triage_result.get("severity_score", 0) >= 3:
                    try:
                        response_result = handle_response(alert)
                        alert["response_action"] = json.dumps(response_result)
                        logger.info(f"RESPONSE: {response_result}")
                    except Exception as e:
                        logger.error(f"Response failed: {str(e)}")

                send_sns_alert(alert, triage_result)

                results.append({
                    "alert_id": alert["alert_id"],
                    "rule_name": alert["rule_name"],
                    "severity": alert["severity"],
                    "triage": triage_result,
                    "response": response_result
                })

        except Exception as e:
            logger.error(f"Error in rule {rule.__name__}: {str(e)}")

    if not results:
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "No threats detected"})
        }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": f"Processed {len(results)} alert(s)",
            "results": results
        }, default=str)
    }


def send_sns_alert(alert, triage_result):
    """Send alert notification via SNS with triage context."""
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
        f"Alert ID: {alert['alert_id']}\n\n"
        f"--- AI Triage ---\n"
        f"Severity Score: {triage_result.get('severity_score', 'N/A')}\n"
        f"Recommended Action: {triage_result.get('recommended_action', 'N/A')}\n"
        f"Confidence: {triage_result.get('confidence', 'N/A')}\n"
        f"Reasoning: {triage_result.get('reasoning', 'N/A')}"
    )

    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=message
        )
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {str(e)}")