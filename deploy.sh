
set -e

cd /home/ubuntu/property-defender-frontend

echo ">>> Pulling latest code..."
git fetch origin
git reset --hard origin/main

echo ">>> Activating virtualenv..."
source venv/bin/activate || . venv/bin/activate

echo ">>> Killing old gunicorn (if any)..."
if pgrep gunicorn; then
  pkill gunicorn
fi

echo ">>> Starting gunicorn..."
nohup gunicorn -b 0.0.0.0:5050 app:app --timeout 120 > gunicorn.log 2>&1 &

echo ">>> (Optional) Reload nginx..."
sudo systemctl reload nginx || true

echo ">>> Deploy done."

