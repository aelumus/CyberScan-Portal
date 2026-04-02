#!/bin/bash
set -euo pipefail

# CyberScan Portal — deployment script
# Called by CD pipeline or manually: bash /opt/cyberscan/scripts/deploy.sh

APP_DIR="/opt/cyberscan"
cd "$APP_DIR"

# Check if swap exists, if not, create a 2GB swapfile
if ! swapon --show | grep -q "swapfile"; then
    echo "=== Creating 2GB Swap File ==="
    sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
    echo "Swap created!"
else
    echo "=== Swap already exists ==="
fi

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
