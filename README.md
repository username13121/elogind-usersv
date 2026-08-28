# elogind-usersv

`elogind-usersv` is an elogind-specific launcher and lifecycle supervisor for
per-user service managers. It starts one manager for each user with an eligible
elogind login session and holds a separately verified elogind background
session for the manager's complete lifetime.

The central invariant is:

```text
managed manager alive
    => verified pinning elogind background session alive
    => elogind-owned XDG_RUNTIME_DIR retained
```

The project is Linux-specific. The Rust workspace builds a root daemon, a
single-threaded per-user supervisor, and a PAM session module. Service-manager
backends are trusted executable files and follow
[`docs/backend-protocol-v1.md`](docs/backend-protocol-v1.md).

Implemented core behavior includes:

- login1 reconciliation and eligible-class filtering;
- a bounded, credential-checked PAM request protocol;
- one explicit state machine and helper per UID;
- verified internal `Class=background` PAM leases;
- pidfd manager tracking, strict readiness framing, checked ready actions,
  restart backoff, and graceful/TERM/KILL shutdown;
- deterministic protocol test backends;
- an s6 backend with shallow `s6-svscan` readiness.

Build and test directly from this standalone repository with:

```sh
make test
make
```

Build the Artix split packages independently of any other project with:

```sh
./build.sh --clean
```

The script prints the exact `pacman -U` command for the packages it produced.
It can also install the complete core, s6 backend, and s6 service set:

```sh
./build.sh --install
```

See [`docs/deployment.md`](docs/deployment.md) before installing the PAM
module, and [`docs/security.md`](docs/security.md) for the trust and lifetime
model. Real elogind/PAM lifecycle validation is still required on the target
distribution before production deployment.

This is an independent repository with its own build and packaging process.
It is not a general session manager, a login1 implementation, an owner of
runtime directories, or an elogind-compatible API.

## License

`elogind-usersv` is distributed under the GNU General Public License version 3
only (`GPL-3.0-only`). See [`LICENSE`](LICENSE).
