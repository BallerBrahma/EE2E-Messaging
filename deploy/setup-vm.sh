#!/usr/bin/env bash
# One-time setup for the relay server on a fresh GCP e2-micro VM (Debian).
# Run this AS ROOT on the VM, after cloning the repo to /opt/e2ee-platform:
#
#   sudo git clone https://github.com/BallerBrahma/EE2E-Messaging.git /opt/e2ee-platform
#   cd /opt/e2ee-platform
#   sudo DOMAIN=your-domain.duckdns.org bash deploy/setup-vm.sh
#
# DOMAIN must already point (an A record) at this VM's static external IP
# before this runs, since Caddy will try to obtain a Let's Encrypt cert for
# it immediately.
set -euo pipefail

REPO_DIR="/opt/e2ee-platform"
DOMAIN="${DOMAIN:?Set DOMAIN=your-domain (e.g. yourname.duckdns.org), pointed at this VM's IP}"

echo "[1/6] Installing system dependencies..."
apt-get update
apt-get install -y python3-venv python3-pip git curl gnupg debian-keyring debian-archive-keyring apt-transport-https

echo "[2/6] Creating service user..."
id -u e2ee &>/dev/null || useradd --system --home "$REPO_DIR" --shell /usr/sbin/nologin e2ee

echo "[3/6] Setting up the app at $REPO_DIR..."
if [ ! -d "$REPO_DIR/.git" ]; then
  echo "Expected a git checkout at $REPO_DIR -- clone the repo there first (see the comment at the top of this script)." >&2
  exit 1
fi
cd "$REPO_DIR"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
chown -R e2ee:e2ee "$REPO_DIR"

echo "[4/6] Installing the systemd service..."
cp deploy/e2ee-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now e2ee-relay

echo "[5/6] Installing Caddy..."
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy

echo "[6/6] Configuring Caddy for $DOMAIN..."
sed "s/your-domain.example.com/$DOMAIN/" deploy/Caddyfile > /etc/caddy/Caddyfile
systemctl reload caddy

echo ""
echo "Done. Check status with:"
echo "  systemctl status e2ee-relay"
echo "  systemctl status caddy"
echo "Relay server should be reachable at wss://$DOMAIN once DNS + the cert are live."
