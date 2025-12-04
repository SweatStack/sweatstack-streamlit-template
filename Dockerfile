FROM ghcr.io/astral-sh/uv:bookworm-slim

ENV PYTHONUNBUFFERED=1
ENV UV_PROJECT_ENVIRONMENT=/venv
ENV UV_COMPILE_BYTECODE=1
ENV PATH="/root/.local/bin:$PATH"
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_INSTALL_DIR=/python
ENV UV_PYTHON_PREFERENCE=only-managed

RUN uv python install 3.13

ADD . /app
WORKDIR /app
RUN uv venv
RUN uv sync --locked

# System deps: curl for uv installer, and supervisor
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl supervisor && \
    rm -rf /var/lib/apt/lists/*


# Copy project metadata first (better Docker cache)
COPY pyproject.toml .

# Copy application code & supervisord config
COPY streamlit_app.py proxy.py supervisord.conf ./

EXPOSE 8080

CMD ["supervisord", "-c", "/app/supervisord.conf"]