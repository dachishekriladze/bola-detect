import json
from pathlib import Path

import pandas as pd
import streamlit as st

RULES = ["B1_distinct_objects", "B2_consecutive_ids", "B3_first_access", "B4_request_rate",
         "B5_failed_requests", "A1_unauthorized_access"]
SEVERITIES = ["confirmed", "attempted", "suspicious"]

st.set_page_config(page_title="bola-detect", layout="wide")
st.title("IDOR/BOLA detection: live alerts")

alerts_path = st.sidebar.text_input("Alerts file", "logs/alerts.jsonl")
refresh = st.sidebar.slider("Refresh every (seconds)", 1, 10, 2)
selected_rules = st.sidebar.multiselect("Rules", RULES, default=RULES)
selected_severity = st.sidebar.multiselect("Severity", SEVERITIES, default=SEVERITIES)
st.sidebar.caption(
    "B1-B5 are behavioral: they see only the request log and can say 'suspicious'. "
    "A1 also uses ownership data and can say 'confirmed' (a request to someone else's object succeeded)."
)


def load_alerts(path):
    p = Path(path)
    if not p.exists():
        return []
    alerts = []
    with open(p, encoding="utf-8") as f:
        for number, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            record["id"] = number
            alerts.append(record)
    return alerts


@st.fragment(run_every=refresh)
def live_view():
    alerts = [a for a in load_alerts(alerts_path)
              if a["rule"] in selected_rules and a["severity"] in selected_severity]
    if not alerts:
        st.info("No alerts yet. Start the detector (python -m detector.live ...) and generate traffic.")
        return

    latest = alerts[-1]
    banner = st.error if latest["severity"] == "confirmed" else st.warning
    banner(f"Latest alert: {latest['rule']} ({latest['severity']}), user {latest['user']}: {latest['details']}")

    frame = pd.DataFrame([{
        "id": a["id"],
        "detected at": a["detected_at"][11:19],
        "event time": a["time"][:19].replace("T", " "),
        "rule": a["rule"],
        "severity": a["severity"],
        "user": a["user"],
        "details": a["details"],
        "evidence": a["evidence_count"],
    } for a in alerts])

    columns = st.columns(4)
    columns[0].metric("Alerts", len(frame))
    columns[1].metric("Confirmed violations", int((frame["severity"] == "confirmed").sum()))
    columns[2].metric("Users flagged", int(frame["user"].nunique()))
    columns[3].metric("Rules firing", int(frame["rule"].nunique()))

    left, right = st.columns([3, 1])
    with left:
        st.subheader("Alerts (newest first)")
        st.dataframe(frame.iloc[::-1], hide_index=True)
    with right:
        st.subheader("Alerts per rule")
        st.bar_chart(frame["rule"].value_counts())

    st.subheader("Evidence")
    by_id = {a["id"]: a for a in alerts}
    ids = [int(i) for i in frame["id"].iloc[::-1]]
    choice = st.selectbox(
        "Alert", ids, key="chosen_alert",
        format_func=lambda i: f"#{i}  {by_id[i]['rule']}  {by_id[i]['user']}  ({by_id[i]['severity']})")
    alert = by_id[choice]
    if alert["evidence"]:
        st.dataframe(pd.DataFrame(alert["evidence"]), hide_index=True)
        st.caption(f"Showing {len(alert['evidence'])} of {alert['evidence_count']} evidence requests.")
    else:
        st.info("The evidence requests are no longer in the detector's memory.")


live_view()