# freetls — portable Makefile.
#
# PY defaults to .venv/bin/python when a project venv exists, else python3.
# GO defaults to `go` on PATH, else ~/.local/go/bin/go. Override either:
#   make test PY=python3.12 GO=/usr/local/go/bin/go
#   make test GO=go FREETLS_GO=go          # (env var honoured by setup.py/tests)
PY ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else command -v python3; fi)
GO ?= $(shell command -v go 2>/dev/null || echo "$(HOME)/.local/go/bin/go")

.DEFAULT_GOAL := help

.PHONY: help venv native native-go native-dynamic test test-fast test-libcrypto test-uquic coverage gen update-openssl setup-caps build fmt lint typecheck clean FORCE

# OpenSSL source + build dir (git submodule) for the wide engine.
OPENSSL_DIR ?= native/third_party/openssl
OPENSSL_JOBS ?= 18

# Guard helpers (single-line so they expand cleanly on a recipe line).
define check_go
@command -v "$(GO)" >/dev/null 2>&1 || { echo "Go toolchain not found. Install Go (https://go.dev/dl) or set GO=/path/to/go."; exit 1; }
endef

define check_openssl_tools
@for t in perl make gcc; do command -v $$t >/dev/null 2>&1 || { echo "The wide engine needs '$$t' on PATH; install it or build the Go-only engine with 'make native-go'."; exit 1; }; done; test -f "$(OPENSSL_DIR)/Configure" || { echo "OpenSSL submodule missing: git submodule update --init --depth 1 $(OPENSSL_DIR)"; exit 1; }
endef

help:
	@echo "freetls targets:"
	@echo "  make venv            create .venv, install freetls[test], build the wide engine"
	@echo "  make native          build native/libfreetls.so = WIDE engine (default; static libcrypto)"
	@echo "  make native-go       build native/libfreetls_go.so = Go-only engine (no OpenSSL)"
	@echo "  make native-dynamic  build native/libfreetls_libcrypto.so = wide engine, dynamic libcrypto (dev)"
	@echo "  make test            full suite (unit + conformance + e2e + pcap)"
	@echo "  make test-fast       same, minus privileged pcap capture"
	@echo "  make test-libcrypto  Go EVP-bridge tests in the uTLS fork"
	@echo "  make coverage        run the suite and enforce the 85% coverage gate"
	@echo "  make gen             regenerate IANA tables + preset map + profile catalog"
	@echo "  make update-openssl TAG=openssl-x.y.z  update the OpenSSL submodule and rebuild"
	@echo "  make setup-caps      one-time: install a cap_net_raw tcpdump under ~/.local"
	@echo "  make build           build sdist + wheel into dist/"
	@echo "  make fmt / lint / typecheck"
	@echo "  make clean           remove build artifacts"

venv:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -e ".[test]"

# Default engine: the WIDE engine (Go + static libcrypto), symbol-hidden so it
# never interposes on the host process (e.g. Python's _ssl).
native: $(OPENSSL_DIR)/libcrypto.a
	$(check_go)
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 \
		CGO_CFLAGS="-I$$PWD/third_party/openssl/include" \
		CGO_LDFLAGS="$$PWD/third_party/openssl/libcrypto.a -ldl -pthread -Wl,-Bsymbolic -Wl,--exclude-libs,ALL" \
		"$(GO)" build -tags "freetls_libcrypto freetls_static_openssl" -buildmode=c-shared -o libfreetls.so .

# Go-only alternate engine (no OpenSSL needed); loaded via use_engine(Engine.GO).
native-go:
	$(check_go)
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" build -buildmode=c-shared -o libfreetls_go.so .

# Wide engine linked against a dynamic system libcrypto (dev / Route B tests).
native-dynamic:
	$(check_go)
	cd native && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" build -tags freetls_libcrypto -buildmode=c-shared -o libfreetls_libcrypto.so .

# Configure flags for the static PIC libcrypto (zstd/brotli/comp disabled so the
# archive has no external transitive deps and embeds cleanly).
OPENSSL_ARGS = linux-x86_64 no-shared no-tests no-zstd no-brotli no-ssl3 no-comp -fPIC

# Static libcrypto.a from the pinned OpenSSL submodule. A stamp records the
# submodule commit + Configure args, so the archive is transparently rebuilt
# after `make update-openssl` (or any submodule/config change).
$(OPENSSL_DIR)/libcrypto.a: FORCE
	$(check_openssl_tools)
	@cur="$$(git -C $(OPENSSL_DIR) rev-parse HEAD 2>/dev/null || echo unknown)"; \
	args='$(OPENSSL_ARGS)'; stamp='$(OPENSSL_DIR)/.freetls-built'; \
	if [ -f "$(OPENSSL_DIR)/libcrypto.a" ] && [ -f "$$stamp" ] && \
	   [ "$$(head -n1 "$$stamp")" = "$$cur" ] && [ "$$(sed -n 2p "$$stamp")" = "$$args" ]; then \
		echo "OpenSSL libcrypto.a is up to date ($$cur)"; \
	else \
		echo "Building static OpenSSL libcrypto.a ($$cur)"; \
		cd "$(OPENSSL_DIR)" && ./Configure $$args && \
			$(MAKE) -j$(OPENSSL_JOBS) build_generated && \
			$(MAKE) -j$(OPENSSL_JOBS) libcrypto.a && \
			printf '%s\n%s\n' "$$cur" "$$args" > "$$stamp"; \
	fi

FORCE:

test-libcrypto:
	cd native/third_party/utls && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 "$(GO)" test -tags freetls_libcrypto -run TestEVP ./...

# uQUIC's packet-protection layer, including the freetls EVP/CCM patch. Needs
# libcrypto on the cgo link line, so it cannot reuse test-libcrypto's flags.
test-uquic:
	cd native/third_party/uquic && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 \
		CGO_CFLAGS="-I$$PWD/../openssl/include" \
		CGO_LDFLAGS="$$PWD/../openssl/libcrypto.a -ldl -pthread" \
		"$(GO)" test -tags freetls_libcrypto -run TestFreetlsCCM ./internal/handshake/
	cd native/third_party/uquic && PATH="$(dir $(GO)):$$PATH" CGO_ENABLED=1 \
		"$(GO)" test -run TestFreetlsCCM ./internal/handshake/

update-openssl:
	sh tools/update_openssl.sh $(TAG)

test: native native-go
	$(PY) -m pytest tests -q

test-fast: native native-go
	$(PY) -m pytest tests -q -m "not pcap"

coverage: native native-go
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
	rm -f native/libfreetls_go.so native/libfreetls_go.dylib native/libfreetls_go.h
	rm -f native/libfreetls_libcrypto.so native/libfreetls_libcrypto.dylib native/libfreetls_libcrypto.h
	rm -f src/freetls/_lib/libfreetls.so src/freetls/_lib/libfreetls.dylib src/freetls/_lib/freetls.dll src/freetls/_lib/libfreetls.h
	rm -f src/freetls/_lib/libfreetls_go.so src/freetls/_lib/libfreetls_go.dylib src/freetls/_lib/libfreetls_go.h
	rm -f src/freetls/_lib/libfreetls_libcrypto.so src/freetls/_lib/libfreetls_libcrypto.dylib src/freetls/_lib/libfreetls_libcrypto.h
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
