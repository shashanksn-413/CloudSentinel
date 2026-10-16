import boto3
import uuid
from datetime import datetime, timezone

dynamodb = boto3.resource("dynamodb", region_name="us-east-2")

alerts_table = dynamodb.Table("cloudsentinel-alerts")
actor_history_table = dynamodb.Table("cloudsentinel-actor-history")
response_log_table = dynamodb.Table("cloudsentinel-response-log")


def store_alert(alert_data):
    """Store a detection alert in DynamoDB."""
    item = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_name": alert_data.get("rule_name", "unknown"),
        "severity": alert_data.get("severity", "MEDIUM"),
        "mitre_technique_id": alert_data.get("mitre_technique_id", ""),
        "mitre_technique_name": alert_data.get("mitre_technique_name", ""),
        "mitre_tactic": alert_data.get("mitre_tactic", ""),
        "actor": alert_data.get("actor", "unknown"),
        "source_ip": alert_data.get("source_ip", "unknown"),
        "event_name": alert_data.get("event_name", ""),
        "event_source": alert_data.get("event_source", ""),
        "description": alert_data.get("description", ""),
        "raw_event": alert_data.get("raw_event", ""),
        "triage_output": alert_data.get("triage_output", ""),
        "response_action": alert_data.get("response_action", "none")
    }
    alerts_table.put_item(Item=item)
    return item


def save_alert(alert):
    """Overwrite a stored alert with its latest triage and response fields."""
    alerts_table.put_item(Item=alert)
    return alert


def store_actor_history(actor_id, alert_summary):
    """Track actor activity over time for stateful triage."""
    item = {
        "actor_id": actor_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert_summary.get("alert_id", ""),
        "rule_name": alert_summary.get("rule_name", ""),
        "severity": alert_summary.get("severity", ""),
        "mitre_technique_id": alert_summary.get("mitre_technique_id", ""),
        "source_ip": alert_summary.get("source_ip", "unknown"),
        "event_name": alert_summary.get("event_name", "")
    }
    actor_history_table.put_item(Item=item)
    return item


def get_actor_history(actor_id, limit=10):
    """Retrieve past alerts for an actor (IP or IAM user)."""
    response = actor_history_table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("actor_id").eq(actor_id),
        ScanIndexForward=False,
        Limit=limit
    )
    return response.get("Items", [])


def store_response_log(response_data):
    """Log an automated response action."""
    item = {
        "response_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_id": response_data.get("alert_id", ""),
        "action_type": response_data.get("action_type", ""),
        "target": response_data.get("target", ""),
        "status": response_data.get("status", ""),
        "details": response_data.get("details", "")
    }
    response_log_table.put_item(Item=item)
    return item