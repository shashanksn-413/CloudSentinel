from datetime import datetime, timezone, timedelta
from src.shared.constants import MITRE_MAPPING

rejected_connections = {}

SCAN_THRESHOLD = 20
SCAN_WINDOW_MINUTES = 5


def evaluate_flow_log(flow_log_record):
    """Detect network scanning from VPC Flow Log rejected connections."""
    source_ip = flow_log_record.get("srcaddr", "unknown")
    dest_port = flow_log_record.get("dstport", 0)
    action = flow_log_record.get("action", "")

    if action != "REJECT":
        return None

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=SCAN_WINDOW_MINUTES)

    if source_ip not in rejected_connections:
        rejected_connections[source_ip] = []

    rejected_connections[source_ip].append({
        "time": now,
        "port": dest_port
    })

    rejected_connections[source_ip] = [
        r for r in rejected_connections[source_ip] if r["time"] > window_start
    ]

    reject_count = len(rejected_connections[source_ip])
    unique_ports = set(r["port"] for r in rejected_connections[source_ip])

    if reject_count >= SCAN_THRESHOLD and len(unique_ports) >= 5:
        mitre = MITRE_MAPPING["network_scanning"]
        return {
            "rule_name": "network_scanning",
            "severity": "MEDIUM",
            "mitre_technique_id": mitre["technique_id"],
            "mitre_technique_name": mitre["technique_name"],
            "mitre_tactic": mitre["tactic"],
            "actor": source_ip,
            "source_ip": source_ip,
            "event_name": "VPC Flow Log - Port Scan",
            "event_source": "vpc-flow-logs",
            "description": f"Network scan detected: {reject_count} rejected connections from {source_ip} across {len(unique_ports)} ports in {SCAN_WINDOW_MINUTES} minutes",
            "raw_event": str(flow_log_record)
        }

    return None