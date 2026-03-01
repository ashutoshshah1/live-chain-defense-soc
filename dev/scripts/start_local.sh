#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but not found."
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip >/dev/null
python -m pip install -e ".[dev]" >/dev/null

HOST="${LCD_HOST:-127.0.0.1}"
PORT="${LCD_PORT:-8000}"

echo "Live Chain Defense starting..."
echo "Dashboard: http://${HOST}:${PORT}/"
echo "Health:    http://${HOST}:${PORT}/health"

exec python -m uvicorn live_chain_defense.app:app --host "${HOST}" --port "${PORT}" --reload
