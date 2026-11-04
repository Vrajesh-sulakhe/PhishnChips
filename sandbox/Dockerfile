FROM mcr.microsoft.com/playwright/python:v1.48.0-noble

# Install python playwright package matching pre-installed browsers
RUN pip install --no-cache-dir playwright==1.48.0

# Create unprivileged runner user
RUN groupadd -g 10001 runner && \
    useradd -u 10001 -g runner -m -d /home/runner -s /bin/bash runner && \
    mkdir -p /app/demo /out && \
    chown -R runner:runner /home/runner /app /out

WORKDIR /app
COPY --chown=runner:runner inspector.py /app/inspector.py
COPY --chown=runner:runner bank_login.html /app/demo/bank_login.html
RUN chmod +x /app/inspector.py

USER runner
ENV PYTHONUNBUFFERED=1 \
    HOME=/home/runner \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

CMD ["python3", "/app/inspector.py"]
