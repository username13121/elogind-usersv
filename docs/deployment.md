# Deployment

`elogind-usersv` changes the login path and must first be tested on a disposable
machine with an independent root console. The implementation targets Linux and
uses pidfds, `SO_PEERCRED`, `SOCK_SEQPACKET`, parent-death signals, and
`openat2` where available.

## Build and install

For a direct source installation:

```sh
make test
make
make DESTDIR="$pkgdir" install
```

For standalone Artix packages, use only this repository's build script:

```sh
./build.sh --clean
```

It produces `elogind-usersv`, `elogind-usersv-backend-s6`, and
`elogind-usersv-s6` under `packages/` and prints their complete installation
command. To build and install all three in one operation:

```sh
./build.sh --install
```

Equivalently, after building:

```sh
sudo pacman -U packages/elogind-usersv-[0-9]*-x86_64.pkg.tar.zst \
  packages/elogind-usersv-backend-s6-*.pkg.tar.zst \
  packages/elogind-usersv-s6-*.pkg.tar.zst
```

Important installed paths are:

```text
/usr/bin/elogind-usersvd
/usr/libexec/elogind-usersv-supervisor
/usr/lib/security/pam_elogind_usersv.so
/usr/libexec/elogind-usersv/backends/s6
/etc/elogind-usersv/config.toml
/etc/pam.d/elogind-usersv-manager
```

Adjust `PREFIX`, `PAMDIR`, and other Make variables for distribution policy.
The private supervisor is not intended to be invoked by users.

## Internal PAM lease

`/etc/pam.d/elogind-usersv-manager` must contain required `pam_elogind` and
must not recursively include `pam_elogind_usersv`:

```pam
session required pam_elogind.so class=background type=unspecified
```

The helper also sets `XDG_SESSION_CLASS=background` and
`XDG_SESSION_TYPE=unspecified` before opening the transaction. This is a
session-only PAM application: it initializes supplementary groups itself and
does not dispatch an authentication stack with `pam_setcred`. Startup fails
unless login1 confirms the expected UID, exact class, service, and runtime
path. Never change this class to `manager`: manager classes do not pin the
elogind user.

## Login PAM stacks

After the daemon is enabled and known to be running, add the module after
`pam_elogind` in each participating service:

```pam
session required pam_elogind.so
session required pam_elogind_usersv.so
```

The default module-side timeout is 35 seconds. An administrator can set a
bounded override, for example:

```pam
session required pam_elogind_usersv.so timeout=60
```

Keep it greater than `login_readiness_timeout_seconds`. Missing
`XDG_SESSION_ID`, missing `XDG_RUNTIME_DIR`, daemon failure, or backend failure
returns `PAM_SESSION_ERR`. `pam_sm_close_session` is intentionally a no-op;
elogind's `SessionRemoved` signal is the logout authority.

Test TTY, SSH, display-manager, lock/unlock, and concurrent login stacks. A
PAM application may connect as root or after changing to the session user;
the daemon accepts only root or the UID resolved from the supplied login1
session.

## System service ordering

The system service graph must have this dependency:

```text
elogind -> elogind-usersvd -> PAM login services
```

On shutdown the edge reverses: PAM login services stop first,
`elogind-usersvd` stops and waits for its helpers, and elogind stops last.

An s6-rc longrun source is provided in `integration/s6-rc/elogind-usersvd`.
Its `dependencies.d/elogind` edge ensures elogind starts first and stops last.
Install it into the system source store and include it in the normal compiled
set before enabling any PAM stack that requires the module:

```sh
make S6_RC_SOURCE_DIR=/etc/s6/sv install-s6
```

Login-service dependency names differ between distributions, so packages must
add explicit dependencies from their display manager, SSH, and console-login
targets to `elogind-usersvd`. Dinit, runit, and OpenRC service definitions are
left to integration packages; they must enforce the same ordering rather than
merely launching both processes.

## s6 backend

The included s6 backend retains shallow readiness: PAM proceeds once
`s6-svscan` has entered its event loop. `s6-user system boot` continues
asynchronously and a slow or failed user service does not revoke readiness.
The backend obtains all frontend paths from `s6-user`, never constructs
`/run/user/$UID`, and avoids replacing boot state while live s6-rc state
exists.

Shutdown first requests `s6-user live stop-everything`, then signals the
tracked `s6-svscan`. The supervisor applies its configured TERM/KILL fallback
if graceful shutdown does not finish.

## Operational checks

For each test user, verify:

1. a real `Class=user` or `Class=user-early` session starts exactly one helper;
2. login1 shows a distinct `Service=elogind-usersv-manager`,
   `Class=background` session;
3. PAM returns only after backend readiness;
4. concurrent logins reuse the same manager PID;
5. closing one of several sessions retains the manager;
6. final logout stops and reaps the manager before the background session
   disappears;
7. killing the manager restarts it while retaining the same background
   session;
8. killing the daemon causes helpers to stop their managers and close leases;
9. restarting the daemon does not overlap old and new managers because of the
   per-UID lock.

`loginctl terminate-user` and manual runtime-directory deletion are forced
administrative operations. They cannot guarantee backend ordering in the same
way as normal final logout.
