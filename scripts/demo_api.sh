#!/usr/bin/env bash
# Thin wrappers for the documented local DockGuard demo. No scanning.
set -euo pipefail
BASE="${REDDOCK_BASE:-http://127.0.0.1:8080}"
auth=(-H "Content-Type: application/json" -H "X-RedDock-Operator-Token: ${TOKEN:?set TOKEN to the local operator token}")

case "${1:-}" in
  settings) curl -s "$BASE/api/settings" | python -m json.tool ;;
  version) curl -s "$BASE/api/version" | python -m json.tool ;;
  create-dockyard)
    curl -s -X POST "$BASE/api/dockyards" "${auth[@]}" \
      -d '{"name":"Local demo workspace"}' | python -m json.tool
    ;;
  add-scope)
    curl -s -X POST "$BASE/api/dockyards/${2}/scope" "${auth[@]}" \
      -d "{\"target\":\"${3}\"}" | python -m json.tool
    ;;
  evaluate)
    curl -s -X POST "$BASE/api/dockyards/${2}/scope/evaluate" "${auth[@]}" \
      -d "{\"target\":\"${3}\"}" | python -m json.tool
    ;;
  *)
    echo "usage: $0 settings|version|create-dockyard|add-scope <id> <target>|evaluate <id> <target>" >&2
    exit 2
    ;;
esac
