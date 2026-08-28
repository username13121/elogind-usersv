# elogind-usersv backend protocol version 1

Backends are trusted, root-installed executable files. They may be binaries,
scripts, or any other executable format supported by the kernel. The backend
path is selected only by system configuration.

Every action runs as the managed user, in that user's home directory (or `/`
under the documented fallback policy), and receives the same sanitized
session environment. The environment includes:

```text
ELOGIND_USERSV_BACKEND_PROTOCOL=1
HOME USER LOGNAME SHELL PATH UID GID
XDG_RUNTIME_DIR XDG_SESSION_ID XDG_SESSION_CLASS XDG_SESSION_TYPE
XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME
```

`XDG_RUNTIME_DIR` is copied from the internal PAM transaction only after it
has been verified against login1. It is never reconstructed from the UID.

## Actions

### `run`

```text
backend run READY_FIFO STATE_DIR CONFIG_DIR
```

`READY_FIFO` and `STATE_DIR` are private per-manager paths created by the
supervisor. `CONFIG_DIR` is a trusted system configuration directory.

The backend prepares the manager, writes exactly one nonempty UTF-8 payload
followed by NUL to `READY_FIFO`, and eventually replaces itself with the
actual manager using `exec`. It must not daemonize. The PID forked by the
supervisor remains the manager PID.

The payload is opaque to elogind-usersv. Version 1 limits it to 4096 bytes.
The supervisor rejects EOF before NUL, an empty or oversized payload, invalid
UTF-8, bytes after the first message, manager exit before a complete message,
and readiness timeout.

### `ready`

```text
backend ready PAYLOAD
```

This action validates or advances the backend-defined login milestone. Exit
status zero succeeds. A nonzero exit, signal, timeout, or manager death is a
startup failure.

### `stop`

```text
backend stop MANAGER_PID
```

Exit zero means that a graceful stop was requested, not that the manager has
exited. Regardless of hook status, the supervisor waits for the manager,
sends `SIGTERM` through its pidfd after the graceful timeout, then sends
`SIGKILL` after the forced timeout and reaps it.

## Lifetime invariant

A `run` action is never started until the daemon accepts the helper's verified
internal elogind `Class=background` lease. The helper retains that same lease
across manager restart attempts and closes it only after the tracked manager
has exited.
