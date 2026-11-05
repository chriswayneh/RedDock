#!/usr/bin/env bash
# Thin wrappers for the documented local DockGuard demo. No scanning.
set -euo pipefail

BASE="${REDDOCK_BASE:-http://127.0.0.1:8080}"
# L1: loopback only.
if [[ ! "$BASE" =~ ^http://(127\.0\.0\.1|localhost):[0-9]+$ ]]; then
  echo "REDDOCK_BASE must be http://127.0.0.1:<port> or http://localhost:<port> (got: $BASE)" >&2
  exit 2
fi

auth=(-H "Content-Type: application/json" -H "X-RedDock-Operator-Token: ${TOKEN:?set TOKEN to the local operator token}")

json_target() {
  python3 -c 'import json,sys; print(json.dumps({"target": sys.argv[1]}))' "$1"
}

require_dockyard_id() {
  if [[ ! "${1:-}" =~ ^[0-9]+$ ]]; then
    echo "dockyard id must be digits only (got: ${1:-})" >&2
    exit 2
  fi
}

case "${1:-}" in
  settings) curl -s "$BASE/api/settings" | python3 -m json.tool ;;
  version) curl -s "$BASE/api/version" | python3 -m json.tool ;;
  create-dockyard)
    curl -s -X POST "$BASE/api/dockyards" "${auth[@]}" \
      -d '{"name":"Local demo workspace"}' | python3 -m json.tool
    ;;
  add-scope)
    require_dockyard_id "${2:-}"
    curl -s -X POST "$BASE/api/dockyards/${2}/scope" "${auth[@]}" \
      -d "$(json_target "${3:?target required}")" | python3 -m json.tool
    ;;
  evaluate)
    require_dockyard_id "${2:-}"
    curl -s -X POST "$BASE/api/dockyards/${2}/scope/evaluate" "${auth[@]}" \
      -d "$(json_target "${3:?target required}")" | python3 -m json.tool
    ;;
  *)
    echo "usage: $0 settings|version|create-dockyard|add-scope <id> <target>|evaluate <id> <target>" >&2
    exit 2
    ;;
esac
