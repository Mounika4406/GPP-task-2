############################
# Stage 1: Builder
############################
FROM python:3.11-slim AS builder

# Work in /app
WORKDIR /app

# Install build tools (if needed for cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file and install
COPY requirements.txt .

# Install Python dependencies into a separate prefix (/install) for copying later
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt


############################
# Stage 2: Runtime
############################
FROM python:3.11-slim AS runtime

# Timezone: UTC (critical!)
ENV TZ=UTC

# Workdir for app
WORKDIR /app

# Install system dependencies: cron + tzdata
RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata && \
    # Configure timezone to UTC
    ln -snf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    # Clean up apt cache
    rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . /app

# Make sure start script is executable
RUN chmod +x /app/start.sh

# Setup cron job (if cron/2fa-cron exists)
RUN mkdir -p /cron /data && \
    chmod 755 /cron /data && \
    if [ -f /app/cron/2fa-cron ]; then \
        chmod 0644 /app/cron/2fa-cron && \
        crontab /app/cron/2fa-cron; \
    fi

# Volume mount points
VOLUME ["/data", "/cron"]

# Expose API port
EXPOSE 8080

# Start cron and API server
CMD ["/app/start.sh"]
