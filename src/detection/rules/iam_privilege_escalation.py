from src.shared.constants import MITRE_MAPPING

ESCALATION_ACTIONS = [
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy",
    "AddUserToGroup"
]


def evaluate(event):
    """Detect IAM privilege escalation attempts by non-admin users."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name not in ESCALATION_ACTIONS:
        return None

    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")

    if user_identity.get("type") == "Root":
        return None

    request_params = detail.get("requestParameters", {})
    target_user = request_params.get("userName", "")
    target_role = request_params.get("roleName", "")
    policy_arn = request_params.get("policyArn", "")
    target = target_user or target_role or "unknown"

    mitre = MITRE_MAPPING["iam_privilege_escalation"]
    return {
        "rule_name": "iam_privilege_escalation",
        "severity": "HIGH",
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "actor": actor,
        "source_ip": source_ip,
        "event_name": event_name,
        "event_source": detail.get("eventSource", "iam.amazonaws.com"),
        "description": f"IAM escalation: {actor} performed {event_name} on {target} (policy: {policy_arn})",
        "raw_event": str(detail)
    }