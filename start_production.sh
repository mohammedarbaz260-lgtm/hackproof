#!/bin/bash
set -e

exec gunicorn \
  --bind 127.0.0.1:5000 \
  --workers 2 \
  --timeout 120 \
  web_app:app
