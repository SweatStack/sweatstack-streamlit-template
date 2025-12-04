import os

import streamlit as st
from sweatstack.streamlit import StreamlitAuth

APP_URL = os.getenv("APP_URL", "http://localhost:8080")

st.title("SweatStack Streamlit template")

auth = StreamlitAuth.behind_proxy(redirect_uri=f"{APP_URL}/auth/callback")
auth.authenticate(show_logout=False)

if not auth.is_authenticated():
    st.write("Please log in to continue")
    st.stop()


with st.sidebar:
    auth.logout_button()
    auth.select_user()


st.write("Welcome to SweatStack")
latest_activity = auth.client.get_latest_activity()
st.write(f"Latest activity: {latest_activity.sport.display_name()} on {latest_activity.start}")