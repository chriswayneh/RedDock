.PHONY: up up-ai up-postgres up-postgres-ai down down-ai down-postgres build logs test test-backend test-frontend lint smoke backup-sqlite verify-sqlite-backup restore-sqlite-backup recover-sqlite-restore reset-data

BACKUP_FILE ?= reddock-backup.rdbackup
BACKUP_HOST_DIR ?= $(if $(REDDOCK_BACKUP_DIR),$(REDDOCK_BACKUP_DIR),./backups)

up:
	docker compose up --build

up-ai:
	docker compose -f compose.yaml -f compose.ollama.yaml up --build

up-postgres:
	docker compose -f compose.yaml -f compose.postgres.yaml up --build

up-postgres-ai:
	docker compose -f compose.yaml -f compose.postgres.yaml -f compose.ollama.yaml up --build

down:
	docker compose down

down-ai:
	docker compose -f compose.yaml -f compose.ollama.yaml down

down-postgres:
	docker compose -f compose.yaml -f compose.postgres.yaml down

build:
	docker compose build

logs:
	docker compose logs -f

test: test-backend test-frontend

test-backend:
	docker build --target runtime -t reddock:local .
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace/backend --entrypoint sh reddock:local -c "pip install -e '.[dev]' && pip-audit --progress-spinner off . && python -m ruff check app tests ../scripts/verify_release.py && python -m pytest"

test-frontend:
	docker run --rm -v "$(CURDIR)/frontend:/workspace" -w /workspace node:22-alpine sh -c "npm ci && npm run security:deps && npm audit --audit-level=high && npm run lint && npm run check && npm run test && npm run build"

smoke:
	docker compose up -d --build
	python scripts/smoke_test.py

backup-sqlite: down
	docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-backup
	docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-backup create --data-dir /var/lib/reddock --output "/backups/$(BACKUP_FILE)" --confirm-offline

verify-sqlite-backup:
	docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-verify
	docker compose -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-verify verify --archive - < "$(BACKUP_HOST_DIR)/$(BACKUP_FILE)"

restore-sqlite-backup: down
	docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-restore
	docker compose -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-restore restore --data-dir /var/lib/reddock --archive - --confirm-offline --confirm-replace < "$(BACKUP_HOST_DIR)/$(BACKUP_FILE)"

recover-sqlite-restore: down
	docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-recover
	docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-recover recover --data-dir /var/lib/reddock --confirm-offline --confirm-rollback

lint:
	docker run --rm -v "$(CURDIR)/backend:/workspace" -w /workspace python:3.13-slim sh -c "pip install ruff && python -m ruff check app tests"

reset-data:
	docker compose down -v
