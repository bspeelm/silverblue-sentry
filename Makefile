# sentry: thin wrappers around cargo, so the common paths are one command.

BINARY := sentry
BINDIR ?= $(HOME)/.local/bin

.PHONY: all build test check install-binary uninstall-binary clean

all: build

build:
	cargo build --release

test:
	cargo test

# The gate from CLAUDE.md: everything must pass before a commit.
check: build
	cargo test
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

install-binary: build
	install -Dm755 target/release/$(BINARY) $(BINDIR)/$(BINARY)
	@echo "installed to $(BINDIR)/$(BINARY)"

# Leaves ~/.config/sentry, ~/.local/share/sentry and the cache alone.
uninstall-binary:
	rm -f $(BINDIR)/$(BINARY)

clean:
	cargo clean
