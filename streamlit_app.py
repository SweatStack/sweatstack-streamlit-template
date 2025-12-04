import os

import streamlit as st
from sweatstack.streamlit import StreamlitAuth


st.title("SweatStack Streamlit template")

headers = st.context.headers
token = headers.get("SweatStack-Access-Token")

auth = StreamlitAuth(
    client_id="YOUR_APPLICATION_ID",
    client_secret="YOUR_APPLICATION_SECRET",
    redirect_uri="http://localhost:8501",
)
auth._set_api_key(token)

if not auth.is_authenticated():
    st.write("Please log in to continue")
    st.stop()


with st.sidebar:
    auth.select_user()


st.write("Welcome to SweatStack")
latest_activity = auth.client.get_latest_activity()
st.write(f"Latest activity: {latest_activity.sport.display_name()} on {latest_activity.start}")