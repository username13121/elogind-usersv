# elogind-usersv

> [!WARNING]
> **Work in progress.** Bugs and breaking changes are expected. This project
> modifies the login path; test it on a disposable system with independent
> recovery access before relying on it.

`elogind-usersv` is an elogind-specific launcher and lifecycle supervisor for
per-user service managers. It starts one selected backend for each user with
an eligible elogind login session and retains a separately verified elogind
background session for the manager's complete lifetime.

```text
managed manager alive
    => verified pinning elogind background session alive
    => elogind-owned XDG_RUNTIME_DIR retained
```

Backends are trusted root-installed executables following
[`docs/backend-protocol-v1.md`](docs/backend-protocol-v1.md). The daemon has no
default backend: the administrator must explicitly choose an installed backend
by name.

The included backend is named **s6-user**. It integrates the independent
[`s6-user`](https://github.com/username13121/s6-user) policy wrapper and does
not claim to be an official s6 per-user implementation.

## Packages

- **elogind-usersv** — daemon, per-UID supervisor, PAM module, and safe
  `/etc/pam.d/system-login` integration utility.
- **elogind-usersv-backend-s6-user** — per-user s6-svscan/s6-rc backend using
  the s6-user package.
- **elogind-usersv-s6** — system s6-rc service definition. It does not select
  or depend on a per-user backend.

## Install without compiling

After installing the s6-user project packages, download the unsigned
`.pkg.tar.zst` files and `SHA256SUMS` from the official
[GitHub Releases page](https://github.com/username13121/elogind-usersv/releases/latest):

```sh
sha256sum -c SHA256SUMS
sudo pacman -U ./*.pkg.tar.zst
```

## Build from source

Install Cargo and the normal package build tools first. The script builds only;
it never invokes pacman or resolves dependencies.

```sh
git clone https://github.com/username13121/elogind-usersv.git
cd elogind-usersv
./build.sh --clean && sudo pacman -U ./packages/*.pkg.tar.zst
```

It writes package checksums to `packages/SHA256SUMS`.

## Required setup

1. Set `backend = "s6-user"` in `/etc/elogind-usersv/config.toml`.
2. Enable and start the system `elogind-usersvd` service.
3. Confirm the daemon is running.
4. Run `sudo elogind-usersv-pam enable`.
5. Fully log out and log back in.

See [`docs/deployment.md`](docs/deployment.md) before changing PAM,
[`docs/security.md`](docs/security.md) for the trust model, and
[`docs/releasing.md`](docs/releasing.md) for the unsigned release procedure.
Run `make test-live` on the target Artix system before production use.

This project is Linux-specific and is not a login1 implementation, general
session manager, or owner of runtime directories.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
