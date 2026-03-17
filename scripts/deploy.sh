#!/bin/bash
set -euo pipefail

# CyberScan Portal — deployment script
# Called by CD pipeline or manually: bash /opt/cyberscan/scripts/deploy.sh

APP_DIR="/opt/cyberscan"
cd "$APP_DIR"

echo "=== Pulling latest code ==="
git pull origin main

echo "=== Building containers ==="
docker compose build

echo "=== Restarting services ==="
docker compose up -d --force-recreate

echo "=== Cleaning old images ==="
docker image prune -f

echo "=== Deploy complete ==="
docker compose ps
