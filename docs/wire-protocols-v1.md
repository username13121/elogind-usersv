# Local wire protocols version 1

Both local protocols use one bounded message per Linux `SOCK_SEQPACKET`
record. The common 12-byte header is:

```text
0..4   ASCII EUSV
4..6   version, unsigned big endian (1)
6..8   message kind, unsigned big endian
8..12  payload length, unsigned big endian
```

Packets are limited to 8192 bytes. Strings use a two-byte big-endian byte
length followed by UTF-8 bytes. Strings are bounded by field before allocation
and may not contain NUL.

## PAM protocol

The request is `EnsureManagerReady { session_id, runtime_dir }`. Session IDs
are limited to 256 bytes and paths to 4096 bytes. Neither value establishes
identity: the daemon obtains the UID and runtime path from login1 and compares
them with the request. The daemon also checks `SO_PEERCRED`.

Replies are `Ready` or `Error { code, message }`. PAM receives deliberately
generic messages; detailed causes are written to daemon logs.

## Daemon/helper protocol

The helper reports its internal lease before starting a backend. The daemon
accepts or rejects that lease after login1 and filesystem verification. The
daemon then explicitly commands each manager start, preserving centralized
state and backoff policy while the helper retains the PAM lease.

Daemon commands are lease acceptance/rejection, start with attempt number,
stop, and shutdown. Helper events report lease opening, manager PID, readiness
payload, successful ready action, startup failure, manager exit status,
shutdown completion, and fatal failure.

EOF on the inherited control socket is an unconditional helper shutdown
request: it stops and reaps the manager, closes the internal PAM session, and
exits.
