MITRE_MAPPING = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access"
    },
    "impossible_travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion"
    },
    "s3_enumeration": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection"
    },
    "iam_privilege_escalation": {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation"
    },
    "network_scanning": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery"
    },
    "new_ip_access_key": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access"
    },
    "root_account_usage": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation"
    },
    "security_group_modification": {
        "technique_id": "T1562.007",
        "technique_name": "Impair Defenses: Disable or Modify Cloud Firewall",
        "tactic": "Defense Evasion"
    }
}

ALERTS_TABLE = "cloudsentinel-alerts"
ACTOR_HISTORY_TABLE = "cloudsentinel-actor-history"
RESPONSE_LOG_TABLE = "cloudsentinel-response-log"


SNS_TOPIC_ARN = "arn:aws:sns:us-east-2:067680447993:cloudsentinel-alerts-topic"

SEVERITY = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10
S3_ENUM_THRESHOLD = 10
S3_ENUM_WINDOW_MINUTES = 5
SENSITIVE_PORTS = [22, 3389, 445, 3306, 5432]