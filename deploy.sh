#!/usr/bin/env bash
# deploy.sh - 1-Click Deployment Automation to Vultr VM
set -euo pipefail

SERVER_IP="139.84.159.12"
KEY_PATH="${HOME}/.ssh/vultr"
HTTPS_DOMAIN="${SERVER_IP}.sslip.io"

echo "=========================================================="
echo "    PHISH&CHIPS: DEPLOYING TO VULTR VM (${SERVER_IP})     "
echo "=========================================================="

echo "==> Step 0: Building production frontend assets..."
npm run build

echo "==> Step 1: Syncing workspace files to Vultr VM..."
rsync -avz --delete \
  --exclude '.env*' \
  --exclude '.venv' \
  --exclude 'backend/venv' \
  --exclude 'backend/__pycache__' \
  --exclude 'node_modules' \
  --exclude '.superpowers' \
  --exclude 'evidence' \
  --exclude '/data' \
  --exclude '*.db*' \
  --exclude 'logs' \
  --exclude '.git' \
  --exclude '.DS_Store' \
  --exclude '__pycache__' \
  --exclude 'rea' \
  -e "ssh -i $KEY_PATH" \
  ./ root@${SERVER_IP}:/root/phish-n-chips/

echo "==> Step 2: Executing VM provisioning & build pipeline..."
ssh -i "$KEY_PATH" root@${SERVER_IP} << 'REMOTE_EXEC'
  set -euo pipefail

  cd /root/phish-n-chips

  echo "--> Ensuring directories exist..."
  mkdir -p evidence logs data backend/data scripts backend frontend sandbox demo/fake-pages deploy

  echo "--> Ensuring production guardrails in .env..."
  if [ -f .env ]; then
    sed -i 's/^TOTAL_BUDGET_SECONDS=.*/TOTAL_BUDGET_SECONDS=60/' .env 2>/dev/null || true
    grep -q "TOTAL_BUDGET_SECONDS" .env || echo "TOTAL_BUDGET_SECONDS=60" >> .env
    grep -q "MAX_QUEUE_DEPTH" .env || echo "MAX_QUEUE_DEPTH=50" >> .env
    grep -q "REPUTATION_TOP_N" .env || echo "REPUTATION_TOP_N=10000" >> .env
    sed -i 's/^SCAN_TIMEOUT_SECONDS=.*/SCAN_TIMEOUT_SECONDS=20/' .env 2>/dev/null || true
    chmod 600 .env
  fi

  echo "--> Setting up phishnet isolated network & iptables containment..."
  bash scripts/setup_network.sh

  echo "--> Building phishchips-sandbox Docker image..."
  docker build -t phishchips-sandbox ./sandbox

  echo "--> Updating Python dependencies in backend/venv..."
  cd /root/phish-n-chips/backend
  if [ ! -d "venv" ]; then
    python3 -m venv venv
  fi
  source venv/bin/activate
  pip install --no-cache-dir -r requirements.txt

  echo "--> Configuring systemd service..."
  pkill -9 -f "uvicorn" || true
  cp /root/phish-n-chips/deploy/phishchips.service /etc/systemd/system/phishchips.service
  systemctl daemon-reload
  systemctl enable phishchips.service
  systemctl restart phishchips.service

  echo "--> Checking Caddy reverse proxy..."
  if systemctl is-active --quiet caddy; then
    systemctl reload caddy || systemctl restart caddy
  fi

  sleep 2
  systemctl status phishchips.service --no-pager || true

  echo "--> Health check verification..."
  curl -fsS http://127.0.0.1:8000/health || (echo "Health check failed!" && exit 1)
  echo ""
  echo "--> Metrics check verification..."
  curl -fsS http://127.0.0.1:8000/metrics | grep -E "phishchips_scans|phishchips_active_scans" | head -n 5
  echo ""
REMOTE_EXEC

echo "=========================================================="
echo "🎉 DEPLOYMENT COMPLETE!"
echo "   🔒 Secure HTTPS : https://${HTTPS_DOMAIN}"
echo "   ⚡ Direct HTTP   : http://${SERVER_IP}:8000"
echo "   📊 Metrics       : https://${HTTPS_DOMAIN}/metrics"
echo "=========================================================="
