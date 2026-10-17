import streamlit as st
import plotly.express as px
import pandas as pd
from analysis_engine import analyze_email_complete, generate_threat_report

st.set_page_config(page_title="Phishing Analyzer", layout="wide")

st.title(" AI Phishing Email Analyzer")

# Session history
if "history" not in st.session_state:
    st.session_state.history = []

tab1, tab2, tab3 = st.tabs(["Analyzer", "Dashboard", "About"])

# =========================
# TAB 1 - ANALYZER
# =========================
with tab1:

    email_text = st.text_area("Email Content", height=250)

    from_email = st.text_input("From Email")
    reply_to = st.text_input("Reply-To Email")
    attachments = st.text_input("Attachments (comma separated)")

    if st.button("Analyze Email"):

        attachment_list = [
            a.strip() for a in attachments.split(",")
        ] if attachments else []

        result = analyze_email_complete(
            email_text=email_text,
            attachments=attachment_list,
            from_email=from_email,
            reply_to=reply_to
        )

        report = generate_threat_report(email_text, result)

        st.session_state.history.append(result)

        # Risk display
        st.metric("Risk Score", result["final_score"])
        st.metric("Risk Level", result["risk_level"])

        # Indicators
        st.subheader("Indicators")
        for i in result["indicators"]:
            st.warning(i)

        # AI Report
        st.subheader("AI Threat Report")
        st.markdown(report)

# =========================
# TAB 2 - DASHBOARD
# =========================
with tab2:

    if st.session_state.history:

        df = pd.DataFrame(st.session_state.history)

        st.subheader("Risk Distribution")

        fig = px.pie(df, names="risk_level")
        st.plotly_chart(fig)

        st.subheader("Risk Scores")

        fig2 = px.histogram(df, x="final_score")
        st.plotly_chart(fig2)

        st.metric("Total Emails", len(df))

    else:
        st.info("No data yet")

# =========================
# TAB 3 - ABOUT
# =========================
with tab3:

    st.write("""
    AI-Powered Phishing Email Analyzer

    Features:
    - ML-based detection
    - Rule-based analysis
    - Attachment scanning
    - Header spoof detection
    - OpenRouter AI explanation
    - Dashboard analytics
    """)