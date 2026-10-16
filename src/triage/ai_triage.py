import json
import logging
import os
from openai import OpenAI
from src.shared.db_helpers import get_actor_history
from src.shared.constants import SEVERITY

logger = logging.getLogger()
logger.setLevel(logging.INFO)

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are CloudSentinel's AI security triage agent. You analyze cloud security alerts and provide structured triage assessments.

For each alert, you will receive:
- Alert details (rule name, event, actor, source IP, MITRE ATT&CK mapping)
- Actor history (previous alerts involving this actor/IP)

You must respond with ONLY a valid JSON object (no markdown, no explanation) containing:
{
    "severity_score": <1-5 integer>,
    "severity_label": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
    "confidence": <0.0-1.0 float>,
    "recommended_action": "<isolate|revoke_keys|monitor|dismiss>",
    "reasoning": "<2-3 sentence explanation>",
    "is_repeat_offender": <true|false>,
    "escalation_needed": <true|false>
}

Scoring guidelines:
- severity_score 5 (CRITICAL): Confirmed compromise, active data exfiltration, root account abuse
- severity_score 4 (HIGH): Strong indicators of attack, privilege escalation, brute force success
- severity_score 3 (MEDIUM): Suspicious activity, reconnaissance, anomalous behavior
- severity_score 2 (LOW): Minor policy violations, informational findings
- severity_score 1 (INFO): Baseline activity, no immediate threat

If the actor has triggered multiple alerts before, increase severity by at least 1 level.
If the actor is a repeat offender across different rule types, recommend escalation."""


def triage_alert(alert):
    """Send alert to AI triage agent for severity assessment and action recommendation."""
    actor_id = alert.get("actor", "unknown")
    source_ip = alert.get("source_ip", "unknown")

    actor_history = get_actor_history(actor_id)
    ip_history = []
    if source_ip != actor_id:
        ip_history = get_actor_history(source_ip)

    user_message = json.dumps({
        "alert": {
            "rule_name": alert.get("rule_name", ""),
            "severity": alert.get("severity", ""),
            "mitre_technique_id": alert.get("mitre_technique_id", ""),
            "mitre_technique_name": alert.get("mitre_technique_name", ""),
            "mitre_tactic": alert.get("mitre_tactic", ""),
            "actor": actor_id,
            "source_ip": source_ip,
            "event_name": alert.get("event_name", ""),
            "description": alert.get("description", ""),
            "timestamp": alert.get("timestamp", "")
        },
        "actor_history": {
            "total_previous_alerts": len(actor_history),
            "recent_alerts": actor_history[:5]
        },
        "ip_history": {
            "total_previous_alerts": len(ip_history),
            "recent_alerts": ip_history[:5]
        }
    }, default=str)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            temperature=0.1,
            max_tokens=500
        )

        raw_output = response.choices[0].message.content.strip()

        triage_result = json.loads(raw_output)

        required_fields = [
            "severity_score", "severity_label", "confidence",
            "recommended_action", "reasoning"
        ]
        for field in required_fields:
            if field not in triage_result:
                triage_result[field] = "unknown"

        logger.info(f"AI Triage result for alert {alert.get('alert_id', '')}: {triage_result}")
        return triage_result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse AI response: {raw_output}")
        return {
            "severity_score": SEVERITY.get(alert.get("severity", "MEDIUM"), 3),
            "severity_label": alert.get("severity", "MEDIUM"),
            "confidence": 0.5,
            "recommended_action": "monitor",
            "reasoning": f"AI triage failed to parse. Defaulting to rule severity. Error: {str(e)}",
            "is_repeat_offender": False,
            "escalation_needed": False
        }

    except Exception as e:
        logger.error(f"AI triage failed: {str(e)}")
        return {
            "severity_score": SEVERITY.get(alert.get("severity", "MEDIUM"), 3),
            "severity_label": alert.get("severity", "MEDIUM"),
            "confidence": 0.0,
            "recommended_action": "monitor",
            "reasoning": f"AI triage unavailable. Defaulting to rule severity. Error: {str(e)}",
            "is_repeat_offender": False,
            "escalation_needed": False
        }