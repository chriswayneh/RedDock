.PHONY: up down build logs test test-backend test-frontend lint smoke reset-data

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

test: test-backend test-frontend

test-backend:
	docker build --target runtime -t reddock:local .
	docker run --rm -v "$(CURDIR)/backend:/workspace" -w /workspace --entrypoint sh reddock:local -c "pip install pytest httpx ruff && python -m ruff check app tests && python -m pytest"

test-frontend:
	docker run --rm -v "$(CURDIR)/frontend:/workspace" -w /workspace node:22-alpine sh -c "npm ci && npm run check && npm run test && npm run build"

smoke:
	docker compose up -d --build
	python scripts/smoke_test.py

lint:
	docker run --rm -v "$(CURDIR)/backend:/workspace" -w /workspace python:3.13-slim sh -c "pip install ruff && python -m ruff check app tests"

reset-data:
	docker compose down -v
