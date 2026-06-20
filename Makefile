# ZTAC framework — convenience targets.
# Everything here is a thin wrapper around scripts/ + docker compose so the
# project comes up identically on any device with Docker, bash and openssl.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

.PHONY: help up down restart certs build ps logs test opa-test verify-logs clean

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up: ## Bootstrap (.env + certs + build) and start the whole stack, wait for health.
	@./scripts/bootstrap.sh

down: ## Stop and remove all containers (keeps images).
	@docker compose down

restart: ## Recreate the stack from current code without a full rebuild.
	@docker compose up -d --force-recreate

certs: ## Generate the mTLS PKI (idempotent; --force to regenerate).
	@bash scripts/generate-certs.sh $(ARGS)

build: ## Build all images.
	@docker compose build

ps: ## Show container status.
	@docker compose ps

logs: ## Tail logs for all services (Ctrl-C to stop).
	@docker compose logs -f

test: ## Run the adversarial pytest suite in an isolated venv against the running stack.
	@./scripts/run-tests.sh

opa-test: ## Run the OPA Rego policy unit tests inside the opa container.
	@docker compose exec -T opa /opa test /policies /tmp/ztac-tests 2>/dev/null \
		|| (docker cp opa/tests ztac-opa:/tmp/ztac-tests && docker compose exec -T opa /opa test /policies /tmp/ztac-tests)

verify-logs: ## Verify the Elasticsearch audit hash-chain integrity.
	@./scripts/run-tests.sh --verify-logs-only

clean: ## Stop the stack and remove volumes (audit logs, ES data) and the test venv.
	@docker compose down -v
	@rm -rf .venv-test
