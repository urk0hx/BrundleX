.PHONY: all preflight build test test-unit test-integration test-e2e check fix clean ui ui-bg ui-stop harvest shell setup

SHELL := /bin/bash
IMAGE_NAME ?= brundlex-agent

all: check test

setup:
	@echo "==> Setting up environment..."
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example..."; \
		cp .env.example .env; \
	fi
	@echo "Environment file ready: .env"

preflight:
	@echo "==> Running preflight checks..."
	@if [ ! -f .env ]; then \
		echo "ERROR: .env file missing. Run 'make setup' first."; \
		exit 1; \
	fi
	@if ! command -v podman >/dev/null 2>&1; then \
		echo "ERROR: podman is required but not installed."; \
		exit 1; \
	fi
	@echo "==> Preflight check passed successfully."

build: preflight
	@echo "==> Building container image: $(IMAGE_NAME)..."
	podman build -t $(IMAGE_NAME) -f Containerfile .

shell: preflight
	@echo "==> Entering interactive development shell inside container..."
	podman run --rm -it -v $(CURDIR):/app:Z --env-file .env $(IMAGE_NAME) /bin/bash

check: preflight
	@echo "==> Running static analysis & linting inside container..."
	podman run --rm -v $(CURDIR):/app:Z $(IMAGE_NAME) ruff check .

fix: preflight
	@echo "==> Running autofix for linting inside container..."
	podman run --rm -v $(CURDIR):/app:Z $(IMAGE_NAME) ruff check --fix .

test: test-unit test-e2e

test-unit: preflight
	@echo "==> Running unit tests inside container..."
	podman run --rm -v $(CURDIR):/app:Z --env-file .env $(IMAGE_NAME) python3 -m pytest tests/unit -v

test-e2e: preflight
	@echo "==> Running end-to-end tests inside container..."
	podman run --rm -v $(CURDIR):/app:Z --env-file .env $(IMAGE_NAME) python3 -m pytest tests/e2e -v

test-integration: test-e2e

harvest: preflight
	@echo "==> Running ephemeral trait harvester inside container..."
	podman run --rm -v $(CURDIR):/app:Z --env-file .env $(IMAGE_NAME) python3 tools/harvest_traits.py $(ARGS)

ui: preflight
	@echo "==> Starting BrundleX Single-Page Workspace inside container on port 8501..."
	@$(MAKE) ui-stop
	podman run --rm -it --name brundlex-ui -p 8501:8501 \
		--security-opt label=disable \
		-v $(CURDIR):/app \
		--env-file .env \
		$(IMAGE_NAME) uvicorn server:app --host 0.0.0.0 --port 8501

ui-bg: preflight
	@echo "==> Starting BrundleX Single-Page Workspace in background (container: brundlex-ui)..."
	@$(MAKE) ui-stop
	podman run -d --name brundlex-ui -p 8501:8501 \
		--security-opt label=disable \
		-v $(CURDIR):/app \
		--env-file .env \
		$(IMAGE_NAME) uvicorn server:app --host 0.0.0.0 --port 8501
	@echo "==> Workspace is running at http://192.168.27.140:8501"

ui-stop:
	@if podman ps -a --format '{{.Names}}' | grep -q '^brundlex-ui$$'; then \
		echo "==> Stopping brundlex-ui container..."; \
		podman stop brundlex-ui >/dev/null 2>&1 || true; \
		podman rm -f brundlex-ui >/dev/null 2>&1 || true; \
	fi

clean: ui-stop
	@echo "==> Cleaning up transient and temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf data/uploads/* 2>/dev/null || true
