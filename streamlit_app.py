import os

import streamlit as st
from sweatstack.streamlit import StreamlitAuth

APP_URL = os.getenv("APP_URL", "http://localhost:8080")

st.title("SweatStack Streamlit template 🚀")

auth = StreamlitAuth.behind_proxy(redirect_uri=f"{APP_URL}/auth/callback")
auth.authenticate(show_logout=False)

if not auth.is_authenticated():
    st.write("Please log in to continue")
    st.stop()


with st.sidebar:
    auth.logout_button()
    auth.select_user()


activity = auth.select_activity()

data = auth.client.get_activity_data(activity.id)

if data is None or data.empty:
    st.warning("No data available")
    st.stop()

available_columns = [col for col in data.columns if col not in ["duration", "lap"]]
metric = st.selectbox("Select the column to plot", available_columns)
st.line_chart(data[metric])