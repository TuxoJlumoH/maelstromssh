# Build and install MaelstromSSH.
#
#   make                         # cargo build --release
#   sudo make install            # into /usr/local
#   make install PREFIX=~/.local # per-user, no root
#   make uninstall [PREFIX=...]
#   make dist                    # release tarball in dist/
#   make deb                     # .deb via cargo-deb
#
# `install` only copies files, so it never runs cargo as root; build first.

PREFIX  ?= /usr/local
DESTDIR ?=
CARGO   ?= cargo

BINS    := maelstromssh maelstromssh-tui maelstromssh-gui maelstromssh-web
SIZES   := 16 24 32 48 64 128 256 512
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
ARCH    := $(shell uname -m)
DISTNAME := maelstromssh-$(VERSION)-$(ARCH)-linux

RELEASE := target/release
BINDIR  := $(DESTDIR)$(PREFIX)/bin
SHARE   := $(DESTDIR)$(PREFIX)/share

.PHONY: all build install uninstall dist deb clean

all: build

build:
	$(CARGO) build --release --locked

install:
	@for b in $(BINS); do \
		test -x $(RELEASE)/$$b || { echo "$(RELEASE)/$$b is missing; run 'make' first" >&2; exit 1; }; \
	done
	install -d $(BINDIR)
	install -m755 $(addprefix $(RELEASE)/,$(BINS)) $(BINDIR)/
	install -Dm644 packaging/maelstromssh.desktop $(SHARE)/applications/maelstromssh.desktop
	for s in $(SIZES); do \
		install -Dm644 assets/icon-$$s.png $(SHARE)/icons/hicolor/$${s}x$${s}/apps/maelstromssh.png; \
	done
	install -Dm644 assets/icon.svg $(SHARE)/icons/hicolor/scalable/apps/maelstromssh.svg
	install -Dm644 -t $(SHARE)/doc/maelstromssh README.md HELP.md
	install -Dm644 -t $(SHARE)/licenses/maelstromssh LICENSE-MIT LICENSE-APACHE \
		web/assets/vendor/LICENSE-xterm web/assets/vendor/LICENSE-xterm-addon-fit

uninstall:
	rm -f $(addprefix $(BINDIR)/,$(BINS))
	rm -f $(SHARE)/applications/maelstromssh.desktop
	for s in $(SIZES); do rm -f $(SHARE)/icons/hicolor/$${s}x$${s}/apps/maelstromssh.png; done
	rm -f $(SHARE)/icons/hicolor/scalable/apps/maelstromssh.svg
	rm -rf $(SHARE)/doc/maelstromssh $(SHARE)/licenses/maelstromssh

# A relocatable tree (bin/, share/) plus this Makefile's install layout;
# unpack and copy into /usr/local or ~/.local.
dist: build
	rm -rf dist/$(DISTNAME)
	$(MAKE) install DESTDIR=dist/$(DISTNAME) PREFIX=
	cp README.md dist/$(DISTNAME)/
	tar -C dist -czf dist/$(DISTNAME).tar.gz $(DISTNAME)
	cd dist && sha256sum $(DISTNAME).tar.gz > $(DISTNAME).tar.gz.sha256
	@echo "dist/$(DISTNAME).tar.gz"

deb: build
	@command -v cargo-deb >/dev/null || { echo "cargo-deb is missing: cargo install cargo-deb" >&2; exit 1; }
	$(CARGO) deb -p maelstromssh --no-build --output dist/

clean:
	$(CARGO) clean
	rm -rf dist
