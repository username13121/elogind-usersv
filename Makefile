PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec
PAMDIR ?= $(PREFIX)/lib/security
SYSCONFDIR ?= /etc
DESTDIR ?=

.PHONY: all test install install-s6 clean

all:
	cargo build --release --locked --workspace

test:
	cargo test --locked --workspace
	cargo clippy --locked --workspace --all-targets -- -D warnings
	sh -n backends/s6 tests/backends/backend-test

install: all
	install -Dm755 target/release/elogind-usersvd \
		$(DESTDIR)$(BINDIR)/elogind-usersvd
	install -Dm755 target/release/elogind-usersv-supervisor \
		$(DESTDIR)$(LIBEXECDIR)/elogind-usersv-supervisor
	install -Dm755 target/release/libpam_elogind_usersv.so \
		$(DESTDIR)$(PAMDIR)/pam_elogind_usersv.so
	install -Dm755 backends/s6 \
		$(DESTDIR)$(LIBEXECDIR)/elogind-usersv/backends/s6
	install -Dm644 config/config.toml \
		$(DESTDIR)$(SYSCONFDIR)/elogind-usersv/config.toml
	install -dm755 $(DESTDIR)$(SYSCONFDIR)/elogind-usersv/backends
	install -Dm644 pam.d/elogind-usersv-manager \
		$(DESTDIR)$(SYSCONFDIR)/pam.d/elogind-usersv-manager
	install -Dm644 docs/backend-protocol-v1.md \
		$(DESTDIR)$(PREFIX)/share/doc/elogind-usersv/backend-protocol-v1.md
	install -Dm644 docs/deployment.md \
		$(DESTDIR)$(PREFIX)/share/doc/elogind-usersv/deployment.md
	install -Dm644 docs/security.md \
		$(DESTDIR)$(PREFIX)/share/doc/elogind-usersv/security.md
	install -Dm644 docs/wire-protocols-v1.md \
		$(DESTDIR)$(PREFIX)/share/doc/elogind-usersv/wire-protocols-v1.md
	install -Dm644 README.md \
		$(DESTDIR)$(PREFIX)/share/doc/elogind-usersv/README.md
	install -Dm644 LICENSE \
		$(DESTDIR)$(PREFIX)/share/licenses/elogind-usersv/LICENSE

# Install this source into the distribution's s6-rc source store. The exact
# store location is distribution policy, so it is intentionally configurable.
S6_RC_SOURCE_DIR ?= /etc/s6/sv
install-s6:
	mkdir -p $(DESTDIR)$(S6_RC_SOURCE_DIR)
	cp -a integration/s6-rc/elogind-usersvd \
		$(DESTDIR)$(S6_RC_SOURCE_DIR)/elogind-usersvd

clean:
	cargo clean
