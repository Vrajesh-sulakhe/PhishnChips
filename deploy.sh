#!/bin/bash
set -e

SERVER_IP="139.84.159.12"
KEY_PATH="$HOME/.ssh/vultr"

echo "==> Syncing code to Vultr VM..."
rsync -avz --exclude 'backend/venv' --exclude 'logs' --exclude 'evidence' --exclude '.git' --exclude 'node_modules' \
  -e "ssh -i $KEY_PATH" ./ root@$SERVER_IP:/root/phish-n-chips/

echo "==> Rebuilding sandbox container & restarting backend..."
ssh -i $KEY_PATH root@$SERVER_IP << 'REMOTE_EXEC'
  cd /root/phish-n-chips
  docker build -t phish-sandbox ./sandbox
  pkill -f uvicorn || true
  cd /root/phish-n-chips/backend
  source venv/bin/activate
  nohup uvicorn main:app --host 0.0.0.0 --port 8000 > /root/phish-n-chips/logs/backend.log 2>&1 &
REMOTE_EXEC

echo "==> Deploy complete! Live at http://$SERVER_IP:8000"
