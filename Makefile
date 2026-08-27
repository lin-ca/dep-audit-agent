.PHONY: help install run dev lint format typecheck test ci clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies (including dev)
	uv sync --extra dev

run: ## Run the CLI against the example pyproject.toml (requires ANTHROPIC_API_KEY)
	uv run dep-audit-agent example_files/example_pyproject.toml

lint: ## Run linting checks
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/

format: ## Format code
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

typecheck: ## Run type checking
	uv run mypy src/

test: ## Run tests
	uv run pytest

ci: lint typecheck test ## Run all checks (lint, typecheck, test)

clean: ## Remove build artifacts and caches
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
