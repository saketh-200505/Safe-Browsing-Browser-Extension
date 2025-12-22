#!/bin/bash
# -------------------------------------------------------------
# Browser Input Sanitizer Sandbox Startup Script
# -------------------------------------------------------------

echo "🔍 Checking and stopping any process on port 8080..."
sudo fuser -k 8080/tcp > /dev/null 2>&1

echo "✅ Activating Python virtual environment..."
cd /home/saketh/sandbox-api || exit
source venv/bin/activate

echo "🚀 Starting Sandbox API on port 8080..."
python3 app.py
