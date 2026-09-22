# gearwit — single public Make interface.

VERSION := $(shell tr -d ' \n\r' < VERSION)
MSRV := $(shell awk -F'"' '/^channel/ { print $$2; exit }' rust-toolchain.toml)
GONEAT_VERSION ?= v0.6.0
PRODUCTION_PACKAGES := -p gearwit-domain -p gearwit-protocol -p gearwit-host -p gearwit-cli

.PHONY: all check gate repository-check goneat-version metadata fmt clippy rust-clippy test rust-test simulator-boundary console-check msrv deny help

all: check

check: repository-check metadata fmt clippy test console-check

gate: check deny

repository-check:
	sh scripts/check-repository.sh

goneat-version:
	@test "$$(goneat --version | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//')" = "$(GONEAT_VERSION:v%=%)" || \
		(echo "goneat version mismatch: expected $(GONEAT_VERSION)" >&2; exit 1)

metadata:
	cargo metadata --locked --no-deps --format-version 1 > /dev/null

fmt:
	cargo fmt --all --check

clippy: rust-clippy simulator-boundary

rust-clippy:
	cargo clippy $(PRODUCTION_PACKAGES) --all-targets --locked -- -D warnings
	cargo clippy -p gearwit-sim --all-targets --locked -- -D warnings

test: rust-test

rust-test:
	cargo test $(PRODUCTION_PACKAGES) --all-targets --locked
	cargo test -p gearwit-sim --all-targets --locked

simulator-boundary:
	@! cargo tree -p gearwit-cli --locked -e features | grep -q 'gearwit-host feature "simulator"'

console-check:
	bun run check:js

msrv:
	cargo +$(MSRV) check $(PRODUCTION_PACKAGES) --locked
	cargo +$(MSRV) check -p gearwit-sim --locked

deny:
	cargo deny check

help:
	@echo "gearwit $(VERSION)"
	@echo "  make check          repository checks + Rust and console checks"
	@echo "  make gate           check + dependency policy"
	@echo "  make msrv           cargo +$(MSRV) check --locked"
	@echo "  make deny           cargo-deny policy"
