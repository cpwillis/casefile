.PHONY: check test live fmt lint demo
check: lint test
test:
	uv run pytest
live:
	uv run pytest -m live -v
lint:
	uv run ruff check
	uv run ruff format --check
fmt:
	uv run ruff format
	uv run ruff check --fix
demo:
	uv run casefile --build-demo site
