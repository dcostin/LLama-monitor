#!/bin/bash
# Standalone monitor startup. By default it watches the model services running
# on THIS machine; to watch another host instead (e.g. the Mac Studio):
#   MONITOR_TARGET_HOST=llama7.local ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

export MONITOR_TARGET_HOST="${MONITOR_TARGET_HOST:-127.0.0.1}"
export MONITOR_PORT="${MONITOR_PORT:-7779}"

if [ -z "${MONITOR_TOKEN:-}" ]; then
  echo "Set MONITOR_TOKEN to the shared access token first, e.g.:" >&2
  echo "  MONITOR_TOKEN='<long random string>' ./run.sh" >&2
  exit 1
fi

if command -v gunicorn >/dev/null 2>&1; then
  exec gunicorn -b "0.0.0.0:$MONITOR_PORT" --workers 2 --threads 4 --worker-class gthread \
    --timeout 120 --access-logfile /tmp/llama-monitor.log --error-logfile /tmp/llama-monitor.log \
    app:app
else
  exec python3 -m flask run --host "0.0.0.0" --port "$MONITOR_PORT"
fi
