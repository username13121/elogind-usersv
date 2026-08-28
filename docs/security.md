# Security and lifetime model

## Authority boundaries

Elogind exclusively owns login sessions, user runtime-directory creation and
removal, seats, and linger state. `elogind-usersv` counts only login1 sessions
whose class is `user` or `user-early`. It never waits for `UserRemoved`, because
the helper's own background session intentionally pins the user object.

The daemon starts only a backend selected by root-owned system configuration.
The configuration file, private supervisor, backend executable, and their
parent directories are checked against symlink traversal and
writable/untrusted ownership before use. Backends run with
NSS-derived supplementary groups and real, effective, and saved UID/GID set to
the target account.

## PAM socket

The control socket is root-owned but connectable by PAM applications running
as either root or the target user. Every packet is bounded and versioned. The
daemon obtains `SO_PEERCRED`; the UID in a login request is never supplied by
the client. It resolves the UID from the login1 session ID and accepts only a
root peer or a peer matching that UID.

The session ID is not treated as a secret. The request's runtime path is also
untrusted and must exactly equal login1's `RuntimePath`.

## Lease verification

Before backend startup the helper opens the internal PAM session and sends its
session ID and runtime path to the daemon. The daemon requires:

- a nonempty session ID;
- the intended UID;
- exact `Class=background`;
- exact `Service=elogind-usersv-manager`;
- PAM `XDG_RUNTIME_DIR` equal to login1 `RuntimePath`;
- an absolute existing directory owned by the target UID;
- no symlink or magic-link traversal.

Linux `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` performs the path
check, with component-by-component `openat(O_NOFOLLOW)` fallback when the
syscall is unavailable.

The helper does not start a backend until the daemon explicitly accepts this
lease. It retains the PAM transaction while managers restart and closes it
only after the final manager is reaped.

## Process safety

The single-threaded helper performs manager forks, privilege changes, and PAM
lifetime management. Manager and backend-action children receive a Linux
parent-death signal and verify their parent after installing it. The helper
tracks the forked manager PID and a pidfd; the backend cannot report or choose
the manager PID.

If daemon control reaches EOF, the helper runs the stop hook, waits, signals
TERM through the pidfd, escalates to KILL if needed, reaps the manager, and
only then closes PAM. A root-owned per-UID `flock` prevents a restarted daemon
from overlapping an old orphaned helper.

The core invariant is therefore preserved on every normal path:

```text
manager alive
    => helper alive with a daemon-verified background session
    => elogind retains its runtime directory
```
