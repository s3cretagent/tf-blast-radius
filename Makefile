.PHONY: help install test check lint types demo graph explain clean

PY ?= python3
VENV := .venv
BIN := $(VENV)/bin
PLAN := examples/plans/dangerous.json

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

$(BIN)/tf-blast-radius:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e '.[dev]'

install: $(BIN)/tf-blast-radius ## create the venv and install in editable mode

test: install ## run the suite — no Terraform binary, no cloud, no network
	$(BIN)/pytest --cov=tfblast --cov-report=term-missing

lint: install ## ruff check + format check
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

types: install ## mypy --strict
	$(BIN)/mypy

check: lint types test ## everything that gates a PR

demo: install ## the run shown at the top of the README
	-@NO_COLOR=1 $(BIN)/tf-blast-radius score $(PLAN) -w prod

graph: install ## trace what depends on the demo database
	@$(BIN)/tf-blast-radius graph $(PLAN) aws_db_instance.orders

explain: install ## print the scoring model and built-in policy
	@$(BIN)/tf-blast-radius explain

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml reports
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
