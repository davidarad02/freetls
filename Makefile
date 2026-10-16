# freetls — portable Makefile.
#
# PY defaults to .venv/bin/python when a project venv exists, else python3.
# GO defaults to `go` on PATH, else ~/.local/go/bin/go. Override either:
#   make test PY=python3.12 GO=/usr/local/go/bin/go
#   make test GO=go FREETLS_GO=go          # (env var honoured by setup.py/tests)
PY ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else command -v python3; fi)
GO ?= $(shell command -v go 2>/dev/null || echo "$(HOME)/.local/go/bin/go")

.DEFAULT_GOAL := help

.PHONY: help venv native libcrypto full test test-fast test-libcrypto coverage gen setup-caps build fmt lint typecheck clean

# Route B: static OpenSSL source + build dir (git submodule).
OPENSSL_DIR ?= native/third_party/openssl
OPENSSL_JOBS ?= 18

help:
	@echo "freetls targets:"
	@echo "  make venv        create .venv and install freetls + test deps (builds engine)"
	@echo "  make native      build native/libfreetls.so from native/*.go (Go-only)"
	@echo "  make libcrypto   build the wide engine (dynamic libcrypto, -tags freetls_libcrypto)"
	@echo "  make full        build the wide engine linked STATICALLY against the OpenSSL submodule"
	@echo "  make test        full suite (unit + conformance + e2e + pcap)"
	@echo "  make test-libcrypto  Go EVP-bridge tests in the uTLS fork"
	@echo "  make test-fast   same, minus privileged pcap capture"
	@echo "  make coverage    run the suite and enforce the 85% coverage gate"
	@echo "  make gen         regenerate IANA tables + preset map + profile catalog"
	@echo "  make setup-caps  one-time: install a cap_net_raw tcpdump under ~/.local"
	@echo "  make build       build sdist + wheel into dist/"
	@echo "  make fmt         format with black + ruff --fix"
	@echo "  make lint        ruff check"
	@echo "  make typecheck   mypy"
	@echo "  make clean       remove build artifacts"

venv:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -e ".[test]"

native:
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		echo "Go toolchain not found. Install Go (https://go.dev/dl) or set GO=/path/to/go."; exit 1; }
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" build -buildmode=c-shared -o libfreetls.so .

# Route B: build the wide (libcrypto-backed) engine. Requires OpenSSL dev files.
libcrypto:
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		echo "Go toolchain not found. Install Go (https://go.dev/dl) or set GO=/path/to/go."; exit 1; }
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" build -tags freetls_libcrypto -buildmode=c-shared -o libfreetls_libcrypto.so .

test-libcrypto:
	cd native/third_party/utls && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" test -tags freetls_libcrypto -run TestEVP ./...

# Build a static, PIC libcrypto.a from the pinned OpenSSL submodule. We disable
# zstd/brotli/comp so the archive has no external transitive dependencies and
# embeds cleanly into libfreetls.so.
$(OPENSSL_DIR)/libcrypto.a:
	@test -f "$(OPENSSL_DIR)/Configure" || { \
		echo "OpenSSL submodule missing. Run:"; \
		echo "  git submodule update --init $(OPENSSL_DIR)"; exit 1; }
	cd "$(OPENSSL_DIR)" && ./Configure linux-x86_64 no-shared no-tests no-zstd no-brotli no-ssl3 no-comp -fPIC
	cd "$(OPENSSL_DIR)" && $(MAKE) -j$(OPENSSL_JOBS) build_generated
	cd "$(OPENSSL_DIR)" && $(MAKE) -j$(OPENSSL_JOBS) libcrypto.a

# Route B "full": the wide engine with libcrypto linked statically and its
# symbols hidden, so it never interposes on the host process (e.g. Python's
# _ssl). Produces native/libfreetls.so.
full: $(OPENSSL_DIR)/libcrypto.a
	@command -v "$(GO)" >/dev/null 2>&1 || { \
		echo "Go toolchain not found. Install Go (https://go.dev/dl) or set GO=/path/to/go."; exit 1; }
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 \
		CGO_CFLAGS="-I$$PWD/third_party/openssl/include" \
		CGO_LDFLAGS="$$PWD/third_party/openssl/libcrypto.a -ldl -pthread -Wl,-Bsymbolic -Wl,--exclude-libs,ALL" \
		"$(GO)" build -tags "freetls_libcrypto freetls_static_openssl" -buildmode=c-shared -o libfreetls.so .

test: native
	$(PY) -m pytest tests -q

test-fast: native
	$(PY) -m pytest tests -q -m "not pcap"

coverage: native
	$(PY) -m pytest tests -q --cov=freetls --cov-report=term-missing --cov-fail-under=85

gen: native
	$(PY) tools/gen_tables.py
	$(PY) tools/gen_presets.py
	$(PY) tools/gen_catalog.py

setup-caps:
	sh scripts/setup_capabilities.sh

fmt:
	$(PY) -m black src tools tests
	$(PY) -m ruff check --fix src tools tests

lint:
	$(PY) -m ruff check src tools tests

typecheck:
	$(PY) -m mypy

build:
	$(PY) -m build

clean:
	rm -rf build dist dist_sdist htmlcov .coverage .pytest_cache
	rm -rf src/freetls.egg-info
	rm -f native/libfreetls.so native/libfreetls.dylib native/freetls.dll native/libfreetls.h
	rm -f native/libfreetls_libcrypto.so native/libfreetls_libcrypto.h
	rm -f src/freetls/_lib/libfreetls.so src/freetls/_lib/libfreetls.dylib src/freetls/_lib/freetls.dll src/freetls/_lib/libfreetls.h
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
