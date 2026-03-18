import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime

st.set_page_config(page_title="Multi-Cloud Security Scanner", page_icon="🔒", layout="wide")

API_URL = "http://localhost:8000"

st.title("🔒 Multi-Cloud Security Scanner")
st.markdown("Scan AWS and Azure for security misconfigurations")

# Sidebar
with st.sidebar:
    st.header("Cloud Provider")
    provider = st.radio("Select Provider", ["AWS", "Azure"])
    
    st.divider()
    
    if provider == "AWS":
        with st.expander("AWS Credentials", expanded=True):
            aws_key = st.text_input("Access Key ID", type="password")
            aws_secret = st.text_input("Secret Access Key", type="password")
            aws_region = st.text_input("Region", value="us-east-1")
    
    if provider == "Azure":
        with st.expander("Azure Credentials", expanded=True):
            sub_id = st.text_input("Subscription ID")
    
    st.divider()
    
    if st.button("🚀 Start Scan", type="primary", use_container_width=True):
        st.session_state['scanning'] = True

# Main content
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Status", "Ready")
with col2:
    st.metric("Provider", provider)
with col3:
    st.metric("Scans", "0")
with col4:
    st.metric("Findings", "0")

# Perform scan
if st.session_state.get('scanning', False):
    with st.spinner(f"Scanning {provider}..."):
        if provider == "AWS":
            payload = {
                "aws_access_key": aws_key if aws_key else None,
                "aws_secret_key": aws_secret if aws_secret else None,
                "region": aws_region
            }
            try:
                response = requests.post(f"{API_URL}/scan/aws", json=payload, timeout=30)
                if response.status_code == 200:
                    st.session_state['results'] = response.json()
                    st.success("✅ Scan complete!")
                else:
                    st.error(f"Error: {response.text}")
            except Exception as e:
                st.error(f"Connection error: {e}")
        
        elif provider == "Azure":
            payload = {"subscription_id": sub_id if sub_id else None}
            try:
                response = requests.post(f"{API_URL}/scan/azure", json=payload, timeout=30)
                if response.status_code == 200:
                    st.session_state['results'] = response.json()
                    st.success("✅ Scan complete!")
                else:
                    st.error(f"Error: {response.text}")
            except Exception as e:
                st.error(f"Connection error: {e}")
    
    st.session_state['scanning'] = False

# Display results
if st.session_state.get('results'):
    results = st.session_state['results']
    
    st.divider()
    st.header(f"📊 {results['provider']} Scan Results")
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Risk Score", f"{results['risk_score']}/100")
    with col2:
        risk_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(results['risk_level'], "⚪")
        st.metric("Risk Level", f"{risk_color} {results['risk_level']}")
    with col3:
        st.metric("Total Issues", results['total_findings'])
    with col4:
        st.metric("Critical Issues", results['summary'].get('CRITICAL', 0))
    
    # Severity chart
    fig = go.Figure(data=[
        go.Bar(
            x=['Critical', 'High', 'Medium', 'Low'],
            y=[
                results['summary'].get('CRITICAL', 0),
                results['summary'].get('HIGH', 0),
                results['summary'].get('MEDIUM', 0),
                results['summary'].get('LOW', 0)
            ],
            marker_color=['red', 'orange', 'gold', 'green']
        )
    ])
    fig.update_layout(title="Findings by Severity", height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # Generate report button
    if st.button("📄 Generate Report"):
        with st.spinner("Generating report..."):
            try:
                report_resp = requests.post(f"{API_URL}/scan/{results['scan_id']}/report")
                if report_resp.status_code == 200:
                    st.success("✅ Report generated in data/reports/")
                else:
                    st.error("Report generation failed")
            except Exception as e:
                st.error(f"Error: {e}")

# Footer
st.divider()
st.markdown("🔒 Multi-Cloud Security Scanner | AWS + Azure")
