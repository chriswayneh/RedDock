#!/usr/bin/env bash
# Re-record docs/assets/demo.gif against a running local RedDock (DockGuard only).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${TMPDIR:-/tmp}/reddock-demo-record-$$"

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

: "${TOKEN:?set TOKEN to the local operator token (never commit it)}"
: "${REDDOCK_BASE:=http://127.0.0.1:8080}"

command -v vhs >/dev/null || { echo "vhs is required" >&2; exit 1; }
command -v ttyd >/dev/null || { echo "ttyd is required by vhs" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

mkdir -p "$STAGE"
cp "$ROOT/scripts/demo.tape" "$STAGE/demo.tape"
cp "$ROOT/scripts/demo_api.sh" "$STAGE/demo_api.sh"
chmod +x "$STAGE/demo_api.sh"

export REDDOCK_DEMO_HOME="$STAGE"
export TOKEN REDDOCK_BASE

# Sanity: settings must answer before we record.
curl -sf "$REDDOCK_BASE/api/settings" >/dev/null

( cd "$STAGE" && vhs demo.tape )

mkdir -p "$ROOT/docs/assets"
cp "$STAGE/demo.gif" "$ROOT/docs/assets/demo.gif"
echo "Wrote $ROOT/docs/assets/demo.gif"
