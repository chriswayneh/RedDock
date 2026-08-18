.PHONY: up down build logs test test-backend test-frontend lint reset-data

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
	docker run --rm --entrypoint sh reddock:local -c "pip install pytest httpx && pytest backend/tests"

test-frontend:
	docker run --rm -v "$(CURDIR)/frontend:/workspace" -w /workspace node:22-alpine sh -c "npm ci && npm run check && npm run test && npm run build"

lint:
	docker run --rm -v "$(CURDIR)/backend:/workspace" -w /workspace python:3.13-slim sh -c "pip install ruff && ruff check app tests"

reset-data:
	docker compose down -v

