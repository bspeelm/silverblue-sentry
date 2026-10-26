# sentry: thin wrappers around cargo, so the common paths are one command.

BINARY := sentry
BINDIR ?= $(HOME)/.local/bin

.PHONY: all build test check install-binary uninstall-binary clean privacy-check

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
	install -Dm755 target/release/sentry-server $(BINDIR)/sentry-server
	@echo "installed to $(BINDIR)/$(BINARY) and $(BINDIR)/sentry-server"

# Leaves ~/.config/sentry, ~/.local/share/sentry and the cache alone.
uninstall-binary:
	rm -f $(BINDIR)/$(BINARY) $(BINDIR)/sentry-server

clean:
	cargo clean

# Private strings (one per line, in the gitignored .private-patterns) must never be published:
# not in tracked files, not in unpushed commit messages, not in a release tarball.
# Run before every commit, push and release: `make privacy-check [TARBALL=path.tar.gz]`.
privacy-check:
	@if [ ! -f .private-patterns ]; then echo "privacy-check: no .private-patterns file, nothing to check"; exit 0; fi
	@if grep -qx '' .private-patterns; then echo "privacy-check: blank line in .private-patterns (it would match everything)"; exit 1; fi
	@if git ls-files -z | xargs -0 grep -I -n -i -F -f .private-patterns; then \
		echo "privacy-check: private strings in tracked files"; exit 1; fi
	@if git log --format=%B @{upstream}..HEAD 2>/dev/null | grep -n -i -F -f .private-patterns; then \
		echo "privacy-check: private strings in unpushed commit messages"; exit 1; fi
	@if [ -n "$(TARBALL)" ] && tar -xzOf "$(TARBALL)" | grep -a -i -o -F -f .private-patterns | sort -u | grep .; then \
		echo "privacy-check: private strings in $(TARBALL)"; exit 1; fi
	@echo "privacy-check: clean"
