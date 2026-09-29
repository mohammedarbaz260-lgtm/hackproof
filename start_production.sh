#!/bin/bash
set -e

exec .venv/bin/gunicorn \
  --bind 0.0.0.0:5000 \
  --workers 2 \
  --access-logfile /tmp/hackproof-access.log \
  --timeout 120 \
  web_app:app
