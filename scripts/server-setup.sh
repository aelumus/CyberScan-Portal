#!/bin/bash
set -euo pipefail

# CyberScan Portal — fresh server provisioning
# Run once on a new Ubuntu 22.04+ VPS

echo "=== Updating system ==="
sudo apt update && sudo apt upgrade -y

echo "=== Installing Docker ==="
sudo apt install -y docker.io docker-compose-plugin git

sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker "$USER"

echo "=== Cloning repository ==="
sudo mkdir -p /opt/cyberscan
sudo chown "$USER":"$USER" /opt/cyberscan
git clone https://github.com/aelumus/CyberScan-Portal.git /opt/cyberscan

echo "=== Creating .env from template ==="
cp /opt/cyberscan/.env.example /opt/cyberscan/.env

echo ""
echo "============================================"
echo "  Server setup complete!"
echo "  Next steps:"
echo "    1. Log out and back in (for docker group)"
echo "    2. Edit /opt/cyberscan/.env"
echo "       - Set JWT_SECRET to a random string"
echo "       - Set SITE_ADDRESS to your domain"
echo "    3. cd /opt/cyberscan && docker compose up -d"
echo "============================================"
