.PHONY: install test lint demo clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -q

lint:
	ruff check .

demo:
	python examples/crm_server.py demo
	python examples/client_demo.py

clean:
	rm -rf .pytest_cache **/__pycache__ *.egg-info .ruff_cache
