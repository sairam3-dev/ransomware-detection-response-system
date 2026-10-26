
import streamlit as st
import pandas as pd
import altair as alt

from app.database.connection import (
    get_recent_alerts,
    get_recent_incidents,
)

st.set_page_config(
    page_title="RDRS SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Ransomware Detection & Response System")
st.caption("Security Operations Center — Monitoring Dashboard")

# Load recent records from SQLite.
alerts = get_recent_alerts(limit=100)
incidents = get_recent_incidents(limit=100)

# Calculate dashboard metrics.
total_alerts = len(alerts)
critical_alerts = sum(
    1 for alert in alerts
    if alert.threat_level.lower() == "critical"
)
open_incidents = sum(
    1 for incident in incidents
    if incident.status.lower() == "open"
)
investigating_incidents = sum(
    1 for incident in incidents
    if incident.status.lower() == "investigating"
)

# Summary metrics.
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical Alerts", critical_alerts)
col3.metric("Open Incidents", open_incidents)
col4.metric("Investigating", investigating_incidents)

st.divider()

# Threat score visualization.
st.subheader("Threat Score Distribution")

if alerts:
    chart_data = pd.DataFrame([
        {
            "Alert ID": alert.id,
            "Threat Score": alert.threat_score,
            "Threat Level": alert.threat_level,
        }
        for alert in alerts
    ])

    chart = alt.Chart(chart_data).mark_bar().encode(
        x=alt.X("Alert ID:O", title="Alert ID"),
        y=alt.Y(
            "Threat Score:Q",
            title="Threat Score (0–100)",
            scale=alt.Scale(domain=[0, 100]),
        ),
        color=alt.Color(
            "Threat Level:N",
            title="Threat Level",
        ),
        tooltip=[
            "Alert ID",
            "Threat Score",
            "Threat Level",
        ],
    ).properties(
        height=300,
    )

    st.altair_chart(chart, use_container_width=True)
else:
    st.info("No alert data is available for visualization.")


# Threat level summary chart.
st.subheader("Threat Level Summary")

if alerts:
    level_counts = (
        pd.DataFrame([
            {"Threat Level": alert.threat_level}
            for alert in alerts
        ])
        .value_counts()
        .rename("Count")
        .reset_index()
    )

    pie_chart = alt.Chart(level_counts).mark_arc(
        innerRadius=60
    ).encode(
        theta=alt.Theta("Count:Q"),
        color=alt.Color(
            "Threat Level:N",
            title="Threat Level",
        ),
        tooltip=["Threat Level", "Count"],
    ).properties(
        height=350,
    )

    st.altair_chart(pie_chart, use_container_width=True)
else:
    st.info("No alert data is available for visualization.")


# Alert table with filters.
st.subheader("Recent Security Alerts")

if alerts:
    alert_data = [
        {
            "ID": alert.id,
            "Title": alert.title,
            "Score": alert.threat_score,
            "Threat Level": alert.threat_level,
            "Status": alert.status,
            "Timestamp": alert.timestamp,
        }
        for alert in alerts
    ]

    alert_df = pd.DataFrame(alert_data)

    col1, col2 = st.columns(2)

    with col1:
        selected_level = st.selectbox(
            "Filter by threat level",
            ["All", "Critical", "Warning", "Normal"],
        )

    with col2:
        selected_status = st.selectbox(
            "Filter by status",
            ["All", "open", "investigating", "resolved"],
        )

    filtered_df = alert_df.copy()

    if selected_level != "All":
        filtered_df = filtered_df[
            filtered_df["Threat Level"] == selected_level
        ]

    if selected_status != "All":
        filtered_df = filtered_df[
            filtered_df["Status"] == selected_status
        ]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(f"Showing {len(filtered_df)} of {len(alert_df)} alerts.")
else:
    st.info("No security alerts found.")



# Incident table with filters.
st.subheader("Incident Tracking")

if incidents:
    incident_data = [
        {
            "ID": incident.id,
            "Alert ID": incident.alert_id,
            "Title": incident.title,
            "Severity": incident.severity,
            "Status": incident.status,
            "Timestamp": incident.timestamp,
        }
        for incident in incidents
    ]

    incident_df = pd.DataFrame(incident_data)

    col1, col2 = st.columns(2)

    with col1:
        selected_severity = st.selectbox(
            "Filter by incident severity",
            ["All", "Critical", "High", "Medium", "Low"],
        )

    with col2:
        selected_incident_status = st.selectbox(
            "Filter by incident status",
            ["All", "open", "investigating", "resolved"],
        )

    filtered_incidents = incident_df.copy()

    if selected_severity != "All":
        filtered_incidents = filtered_incidents[
            filtered_incidents["Severity"] == selected_severity
        ]

    if selected_incident_status != "All":
        filtered_incidents = filtered_incidents[
            filtered_incidents["Status"] == selected_incident_status
        ]

    st.dataframe(
        filtered_incidents,
        use_container_width=True,
        hide_index=True,
    )

    st.caption(
        f"Showing {len(filtered_incidents)} of "
        f"{len(incident_df)} incidents."
    )
else:
    st.info("No incidents found.")


st.divider()

# Download existing report files.
st.subheader("Security Reports")

col1, col2 = st.columns(2)

with col1:
    st.markdown("[Download JSON report](http://127.0.0.1:8081/reports/json)")

with col2:
    st.markdown("[Download CSV alerts report](http://127.0.0.1:8081/reports/csv)")
