#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-8090}"
export CSL_DB_PATH="${CSL_DB_PATH:-$DIR/data/csl_meter.db}"
exec python3 "$DIR/app.py"
