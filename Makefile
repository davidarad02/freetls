# freetls — portable Makefile.
#
# PY defaults to .venv/bin/python when a project venv exists, else python3.
# GO defaults to `go` on PATH, else ~/.local/go/bin/go. Override either:
#   make test PY=python3.12 GO=/usr/local/go/bin/go
#   make test GO=go FREETLS_GO=go          # (env var honoured by setup.py/tests)
PY ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else command -v python3; fi)
GO ?= $(shell command -v go 2>/dev/null || echo "$(HOME)/.local/go/bin/go")

.DEFAULT_GOAL := help

.PHONY: help venv native test test-fast coverage gen setup-caps build clean

help:
	@echo "freetls targets:"
	@echo "  make venv        create .venv and install freetls + test deps (builds engine)"
	@echo "  make native      build native/libfreetls.so from native/*.go"
	@echo "  make test        full suite (unit + conformance + e2e + pcap)"
	@echo "  make test-fast   same, minus privileged pcap capture"
	@echo "  make coverage    run the suite and enforce the 85% coverage gate"
	@echo "  make gen         regenerate IANA tables + profile catalog"
	@echo "  make setup-caps  one-time: install a cap_net_raw tcpdump under ~/.local"
	@echo "  make build       build sdist + wheel into dist/"
	@echo "  make clean       remove build artifacts"

venv:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -e ".[test]"

native:
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		echo "Go toolchain not found. Install Go (https://go.dev/dl) or set GO=/path/to/go."; exit 1; }
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" build -buildmode=c-shared -o libfreetls.so .

test: native
	$(PY) -m pytest tests -q

test-fast: native
	$(PY) -m pytest tests -q -m "not pcap"

coverage: native
	$(PY) -m pytest tests -q --cov=freetls --cov-report=term-missing --cov-fail-under=85

gen: native
	$(PY) tools/gen_tables.py
	$(PY) tools/gen_catalog.py

setup-caps:
	sh scripts/setup_capabilities.sh

build:
	$(PY) -m build

clean:
	rm -rf build dist dist_sdist htmlcov .coverage .pytest_cache
	rm -rf src/freetls.egg-info
	rm -f native/libfreetls.so native/libfreetls.dylib native/freetls.dll native/libfreetls.h
	rm -f src/freetls/_lib/libfreetls.so src/freetls/_lib/libfreetls.dylib src/freetls/_lib/freetls.dll src/freetls/_lib/libfreetls.h
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
