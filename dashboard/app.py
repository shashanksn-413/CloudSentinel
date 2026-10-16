import streamlit as st
import boto3
import json
import pandas as pd
from datetime import datetime, timezone
from boto3.dynamodb.conditions import Key, Attr

REGION = "us-east-2"
dynamodb = boto3.resource("dynamodb", region_name=REGION)
alerts_table = dynamodb.Table("cloudsentinel-alerts")
actor_history_table = dynamodb.Table("cloudsentinel-actor-history")
response_log_table = dynamodb.Table("cloudsentinel-response-log")

st.set_page_config(
    page_title="CloudSentinel Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .severity-critical { color: #FF0000; font-weight: bold; }
    .severity-high { color: #FF6600; font-weight: bold; }
    .severity-medium { color: #FFD700; font-weight: bold; }
    .severity-low { color: #00CC00; font-weight: bold; }
    .severity-info { color: #0099FF; font-weight: bold; }
    .metric-card {
        background-color: #1E1E1E;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data(ttl=30)
def get_all_alerts():
    """Scan all alerts from DynamoDB."""
    response = alerts_table.scan()
    items = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = alerts_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


@st.cache_data(ttl=30)
def get_all_response_logs():
    """Scan all response logs from DynamoDB."""
    response = response_log_table.scan()
    items = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = response_log_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


def get_actor_history(actor_id):
    """Query actor history from DynamoDB."""
    response = actor_history_table.query(
        KeyConditionExpression=Key("actor_id").eq(actor_id),
        ScanIndexForward=False
    )
    return response.get("Items", [])


st.sidebar.title("🛡️ CloudSentinel")
st.sidebar.markdown("Cloud Threat Detection & Automated Response")
page = st.sidebar.radio("Navigate", [
    "Dashboard",
    "Alert Feed",
    "Alert Detail",
    "Actor History",
    "Response Log",
    "Metrics"
])

alerts = get_all_alerts()
response_logs = get_all_response_logs()

if page == "Dashboard":
    st.title("🛡️ CloudSentinel — Security Operations Dashboard")
    st.markdown("---")

    col1, col2, col3, col4, col5 = st.columns(5)

    total_alerts = len(alerts)
    critical_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
    total_responses = len(response_logs)

    col1.metric("Total Alerts", total_alerts)
    col2.metric("Critical", critical_count)
    col3.metric("High", high_count)
    col4.metric("Medium", medium_count)
    col5.metric("Response Actions", total_responses)

    st.markdown("---")

    st.subheader("Recent Alerts")
    if alerts:
        sorted_alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
        for alert in sorted_alerts[:10]:
            severity = alert.get("severity", "UNKNOWN")
            severity_colors = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "INFO": "🔵"
            }
            icon = severity_colors.get(severity, "⚪")
            with st.expander(
                f"{icon} [{severity}] {alert.get('rule_name', 'unknown')} — {alert.get('actor', 'unknown')} ({alert.get('timestamp', '')[:19]})"
            ):
                st.json(alert)
    else:
        st.info("No alerts detected yet. Run attack simulations to generate alerts.")

    st.markdown("---")
    st.subheader("Alerts by Detection Rule")
    if alerts:
        rule_counts = {}
        for a in alerts:
            rule = a.get("rule_name", "unknown")
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        df_rules = pd.DataFrame(
            list(rule_counts.items()),
            columns=["Rule", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(df_rules.set_index("Rule"))

    st.subheader("Alerts by Severity")
    if alerts:
        sev_counts = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        df_sev = pd.DataFrame(
            list(sev_counts.items()),
            columns=["Severity", "Count"]
        )
        st.bar_chart(df_sev.set_index("Severity"))

elif page == "Alert Feed":
    st.title("📋 Real-Time Alert Feed")
    st.markdown("---")

    col1, col2 = st.columns(2)
    severity_filter = col1.multiselect(
        "Filter by Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=["CRITICAL", "HIGH", "MEDIUM"]
    )
    rule_names = list(set(a.get("rule_name", "unknown") for a in alerts))
    rule_filter = col2.multiselect("Filter by Rule", rule_names, default=rule_names)

    filtered = [
        a for a in alerts
        if a.get("severity") in severity_filter and a.get("rule_name") in rule_filter
    ]
    sorted_filtered = sorted(filtered, key=lambda x: x.get("timestamp", ""), reverse=True)

    st.markdown(f"**Showing {len(sorted_filtered)} alerts**")

    for alert in sorted_filtered:
        severity = alert.get("severity", "UNKNOWN")
        severity_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵"
        }
        icon = severity_colors.get(severity, "⚪")

        with st.expander(
            f"{icon} [{severity}] {alert.get('rule_name', '')} | {alert.get('actor', '')} | {alert.get('source_ip', '')} | {alert.get('timestamp', '')[:19]}"
        ):
            col1, col2 = st.columns(2)
            col1.markdown(f"**Rule:** {alert.get('rule_name', '')}")
            col1.markdown(f"**Severity:** {severity}")
            col1.markdown(f"**Actor:** {alert.get('actor', '')}")
            col1.markdown(f"**Source IP:** {alert.get('source_ip', '')}")

            col2.markdown(f"**MITRE ATT&CK:** {alert.get('mitre_technique_id', '')} — {alert.get('mitre_technique_name', '')}")
            col2.markdown(f"**Tactic:** {alert.get('mitre_tactic', '')}")
            col2.markdown(f"**Event:** {alert.get('event_name', '')}")
            col2.markdown(f"**Time:** {alert.get('timestamp', '')}")

            st.markdown(f"**Description:** {alert.get('description', '')}")

            triage = alert.get("triage_output", "")
            if triage:
                st.markdown("**AI Triage Output:**")
                try:
                    st.json(json.loads(triage))
                except (json.JSONDecodeError, TypeError):
                    st.text(str(triage))

elif page == "Alert Detail":
    st.title("🔍 Alert Detail View")
    st.markdown("---")

    if alerts:
        alert_options = {
            f"{a.get('rule_name', '')} | {a.get('actor', '')} | {a.get('timestamp', '')[:19]}": a
            for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
        }
        selected = st.selectbox("Select an alert", list(alert_options.keys()))
        alert = alert_options[selected]

        col1, col2, col3 = st.columns(3)
        col1.metric("Severity", alert.get("severity", ""))
        col2.metric("MITRE Technique", alert.get("mitre_technique_id", ""))
        col3.metric("Event", alert.get("event_name", ""))

        st.markdown("---")
        st.subheader("Alert Details")
        st.json(alert)

        triage = alert.get("triage_output", "")
        if triage:
            st.markdown("---")
            st.subheader("AI Triage Assessment")
            try:
                triage_data = json.loads(triage)
                col1, col2, col3 = st.columns(3)
                col1.metric("Severity Score", f"{triage_data.get('severity_score', 'N/A')}/5")
                col2.metric("Confidence", f"{triage_data.get('confidence', 'N/A')}")
                col3.metric("Recommended Action", triage_data.get("recommended_action", "N/A"))
                st.markdown(f"**Reasoning:** {triage_data.get('reasoning', 'N/A')}")
                st.markdown(f"**Repeat Offender:** {triage_data.get('is_repeat_offender', 'N/A')}")
                st.markdown(f"**Escalation Needed:** {triage_data.get('escalation_needed', 'N/A')}")
            except (json.JSONDecodeError, TypeError):
                st.text(str(triage))

        response = alert.get("response_action", "")
        if response and response != "none":
            st.markdown("---")
            st.subheader("Response Action")
            try:
                st.json(json.loads(response))
            except (json.JSONDecodeError, TypeError):
                st.text(str(response))
    else:
        st.info("No alerts to display.")

elif page == "Actor History":
    st.title("👤 Actor History")
    st.markdown("---")

    actors = list(set(a.get("actor", "unknown") for a in alerts))
    ips = list(set(a.get("source_ip", "unknown") for a in alerts))
    all_actors = sorted(set(actors + ips))

    if all_actors:
        selected_actor = st.selectbox("Select an actor (IAM user or IP)", all_actors)
        history = get_actor_history(selected_actor)

        st.markdown(f"**Total alerts for {selected_actor}:** {len(history)}")

        if history:
            for item in history:
                with st.expander(
                    f"{item.get('rule_name', '')} | {item.get('severity', '')} | {item.get('timestamp', '')[:19]}"
                ):
                    st.json(item)
        else:
            st.info("No history found for this actor.")
    else:
        st.info("No actors found. Run attack simulations first.")

elif page == "Response Log":
    st.title("⚡ Response Action Log")
    st.markdown("---")

    if response_logs:
        sorted_logs = sorted(response_logs, key=lambda x: x.get("timestamp", ""), reverse=True)
        for log in sorted_logs:
            with st.expander(
                f"{log.get('action_type', '')} | {log.get('target', '')} | {log.get('status', '')} | {log.get('timestamp', '')[:19]}"
            ):
                st.json(log)
    else:
        st.info("No response actions logged yet.")

elif page == "Metrics":
    st.title("📊 CloudSentinel Metrics")
    st.markdown("---")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts Generated", len(alerts))
    col2.metric("Total Response Actions", len(response_logs))
    col3.metric("Detection Rules Active", 7)

    st.markdown("---")
    st.subheader("Detection Rules")
    rules_data = [
        {"Rule": "Brute Force Login", "MITRE": "T1110", "Severity": "HIGH"},
        {"Rule": "Root Account Usage", "MITRE": "T1078.004", "Severity": "CRITICAL"},
        {"Rule": "IAM Privilege Escalation", "MITRE": "T1548", "Severity": "HIGH"},
        {"Rule": "S3 Bucket Enumeration", "MITRE": "T1530", "Severity": "MEDIUM"},
        {"Rule": "Security Group Modification", "MITRE": "T1562.007", "Severity": "HIGH"},
        {"Rule": "Impossible Travel", "MITRE": "T1078", "Severity": "HIGH"},
        {"Rule": "New IP Access Key Usage", "MITRE": "T1078.004", "Severity": "MEDIUM"},
        {"Rule": "Network Scanning", "MITRE": "T1046", "Severity": "MEDIUM"}
    ]
    st.table(pd.DataFrame(rules_data))

    st.markdown("---")
    st.subheader("Severity Distribution")
    if alerts:
        sev_counts = {}
        for a in alerts:
            sev = a.get("severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        st.bar_chart(pd.DataFrame(
            list(sev_counts.items()),
            columns=["Severity", "Count"]
        ).set_index("Severity"))

    st.markdown("---")
    st.subheader("MITRE ATT&CK Coverage")
    if alerts:
        mitre_counts = {}
        for a in alerts:
            technique = a.get("mitre_technique_id", "unknown")
            mitre_counts[technique] = mitre_counts.get(technique, 0) + 1
        st.bar_chart(pd.DataFrame(
            list(mitre_counts.items()),
            columns=["Technique", "Count"]
        ).set_index("Technique"))