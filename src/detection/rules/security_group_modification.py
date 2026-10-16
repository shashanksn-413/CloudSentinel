from src.shared.constants import MITRE_MAPPING, SENSITIVE_PORTS

SG_ACTIONS = [
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "ModifySecurityGroupRules"
]


def evaluate(event):
    """Detect security group changes that open sensitive ports to the internet."""
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")

    if event_name not in SG_ACTIONS:
        return None

    user_identity = detail.get("userIdentity", {})
    actor = user_identity.get("arn", user_identity.get("userName", "unknown"))
    source_ip = detail.get("sourceIPAddress", "unknown")
    request_params = detail.get("requestParameters", {})

    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])
    flagged_ports = []

    for perm in ip_permissions:
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 0)
        ip_ranges = perm.get("ipRanges", {}).get("items", [])

        for ip_range in ip_ranges:
            cidr = ip_range.get("cidrIp", "")
            if cidr in ["0.0.0.0/0", "::/0"]:
                for port in SENSITIVE_PORTS:
                    if from_port <= port <= to_port:
                        flagged_ports.append(port)

    if not flagged_ports:
        return None

    group_id = request_params.get("groupId", "unknown")
    mitre = MITRE_MAPPING["security_group_modification"]
    return {
        "rule_name": "security_group_modification",
        "severity": "HIGH",
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique_name": mitre["technique_name"],
        "mitre_tactic": mitre["tactic"],
        "actor": actor,
        "source_ip": source_ip,
        "event_name": event_name,
        "event_source": "ec2.amazonaws.com",
        "description": f"Security group {group_id} opened ports {flagged_ports} to 0.0.0.0/0 by {actor}",
        "raw_event": str(detail)
    }