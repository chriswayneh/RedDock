# Terminal demo

The README GIF replays actual API output from **RedDock v0.8.3** running in
local mode on loopback (2026-11-05, America/Chicago). It exercises DockGuard
and settings only: no discovery, no Nmap, no NSE, no UDP, no brute force, and
no `REDDOCK_DEPLOYMENT_MODE=server`. Timing is adjusted for README readability.

## What it shows

1. `GET /api/version` and `GET /api/settings` — version `0.8.3`, deployment
   mode `local`, intelligence off.
2. Create a fictional Dockyard named `Local demo workspace`.
3. Authorize scope for `127.0.0.1` and evaluate it — DockGuard returns
   `allowed`.
4. Refuse an internet-wide scope (`0.0.0.0/0`) and deny the cloud metadata
   address `169.254.169.254` (`denied_policy`).

No host outside loopback is contacted. The operator token is loaded into an
environment variable off-camera and never appears in the animation.

## Run it yourself

### Option A — Compose (documented release path)

```bash
git clone --branch v0.8.3 --depth 1 https://github.com/chriswayneh/RedDock.git
cd RedDock
docker compose up --build
# in another terminal:
export TOKEN="$(docker compose exec -T reddock cat /var/lib/reddock/operator-token)"
export REDDOCK_BASE=http://127.0.0.1:8080
```

### Option B — Local uvicorn (no Docker)

From a checkout of the `v0.8.3` tag, with Python 3.13:

```bash
cd backend
python3.13 -m venv .venv
.venv/bin/pip install -e .
DEMO_DATA="$(mktemp -d)"
chmod 700 "$DEMO_DATA"
export REDDOCK_DATABASE_URL="sqlite:///$DEMO_DATA/reddock.db"
export REDDOCK_EVIDENCE_DIR="$DEMO_DATA/evidence"
export REDDOCK_OPERATOR_TOKEN_FILE="$DEMO_DATA/operator-token"
export REDDOCK_DEPLOYMENT_MODE=local
.venv/bin/uvicorn app.main:create_app --factory --host 127.0.0.1 --port 18080
# in another terminal (reuse the same DEMO_DATA path):
export TOKEN="$(cat "$DEMO_DATA/operator-token")"
export REDDOCK_BASE=http://127.0.0.1:18080
```

Then, from this repository:

```bash
./scripts/demo_api.sh version
./scripts/demo_api.sh settings
./scripts/demo_api.sh create-dockyard
./scripts/demo_api.sh add-scope 1 127.0.0.1
./scripts/demo_api.sh evaluate 1 127.0.0.1
./scripts/demo_api.sh add-scope 1 0.0.0.0/0
./scripts/demo_api.sh evaluate 1 169.254.169.254
```

Shut down with `docker compose down` (option A) or Ctrl+C on uvicorn
(option B). Do not pass `-v` to Compose unless you intend to delete local data.

## Re-record the GIF

Requires [vhs](https://github.com/charmbracelet/vhs), `ttyd`, and a running
local RedDock instance (option A or B above):

```bash
export TOKEN=...          # operator token; never commit this
export REDDOCK_BASE=http://127.0.0.1:18080   # or :8080 for Compose
./scripts/record-demo.sh
```

`scripts/record-demo.sh` stages a throwaway work directory, records
`docs/assets/demo.gif` from `scripts/demo.tape`, and does not start discovery.

## Text alternative

The [Start here](GETTING_STARTED.md) guide walks the same DockGuard and scope
ideas in the browser against RedDock's own Compose proxy, still without UDP,
NSE, brute force, or server mode.
