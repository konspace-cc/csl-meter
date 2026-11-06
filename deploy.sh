#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"
mkdir -p "$DIR/data" "$DIR/docs"

echo "[deploy.sh] 1. Initializing SQLite WAL database & verifying schema..."
python3 -c "import csl_engine; db = csl_engine.CSLDatabase('$DIR/data/csl_meter.db'); print('Seeded plans:', len(db.list_plans()))"

echo "[deploy.sh] 2. Running unit & contract test suite..."
python3 -m unittest discover -s "$DIR/tests" -v

echo "[deploy.sh] 3. Running 100-run zero-credential retention & 5-threshold security audit..."
python3 "$DIR/scripts/security_audit.py"

echo "[deploy.sh] Build and verification complete."
