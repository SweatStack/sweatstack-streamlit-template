import os

import streamlit as st
import sweatstack


st.title("SweatStack prototype – Streamlit behind FastAPI proxy")

headers = st.context.headers  # Streamlit 1.41+ style contextual headers

st.subheader("Incoming request headers (as seen by Streamlit)")
st.json(headers)

token = headers.get("SweatStack-Access-Token")

if not token:
    st.warning("Not authenticated – no SweatStack-Access-Token header found.")
    st.markdown(
        """
        <p>
        <a href="/login">Login with your OIDC provider</a>
        </p>
        """,
        unsafe_allow_html=True,
    )
else:
    st.success("Authenticated!")
    st.write("SweatStack-Access-Token:", token[:20] + "..." if len(token) > 20 else token)


os.environ["SWEATSTACK_API_KEY"] = token

activity = sweatstack.get_latest_activity()

st.write(activity)