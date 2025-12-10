#!/bin/sh
set -e

# Start cron in the background
cron

# Start FastAPI app with uvicorn on port 8080
uvicorn app:app --host 0.0.0.0 --port 8080

