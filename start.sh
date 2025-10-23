#!/bin/bash
# === AUTO SETUP ===
echo "Installing dependencies..."
pip install --disable-pip-version-check -U --prefix .local -r requirements.txt

# === SETUP ENVIRONMENT ===
export PORT=8080
export FLASK_ENV=production
export SECRET_KEY="your_secret_key_here"

# === START FLASK APP ===
echo "Starting Flask app on port $PORT..."
python3 app.py
