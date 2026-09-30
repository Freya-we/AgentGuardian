.PHONY: install dev dashboard demo-dashboard test test-integration test-watch lint docs ebpf guardian frida-setup clean

install:
	uv sync

dev:
	uv run uvicorn src.engine.server:app --reload --reload-dir src/engine --reload-dir config --host 0.0.0.0 --port 8000

dashboard:
	cd src/dashboard && pnpm dev

demo-dashboard:
	bash scripts/demo_alert.sh

test:
	uv run pytest tests/ -v --cov=src/engine --cov-report=term-missing

test-integration:
	uv run pytest tests/integration/ -v

test-watch:
	uv run watchfiles "uv run pytest tests/ -v -q" tests/ src/engine/

lint:
	uv run ruff check src/engine/ tests/

docs:
	bash docs/manual/build-typst.sh

ebpf:
	$(MAKE) -C src/ebpf

guardian:
	$(MAKE) -C src/causal_guardian

frida-setup:
	uv add frida-tools

clean:
	rm -rf .pytest_cache __pycache__ src/engine/__pycache__ tests/__pycache__
	rm -f docs/technical-manual.typ docs/technical-manual.pdf
	$(MAKE) -C src/ebpf clean
	$(MAKE) -C src/causal_guardian clean
