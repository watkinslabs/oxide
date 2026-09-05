# Windows Winsock Network Events

FROZEN 2026-09-04. Dep:`01`,`02`,`25`,`31d`,`31f`,`31g`,`52`,`53`.

## 1 Ownership

The Linux-shaped socket owner remains authoritative for readiness. The NT
adapter obtains one `InetSocket::poll()` snapshot and translates it through
`net::windows_events`; it stores no readiness, subscription, or error state.

## 2 Projection

| Linux readiness | Listener | Connecting | Connected |
|---|---|---|---|
| `POLL_IN` | `FD_ACCEPT` | `FD_READ` | `FD_READ` |
| `POLL_PRI` | `FD_OOB` | `FD_OOB` | `FD_OOB` |
| `POLL_OUT` | `FD_WRITE` | `FD_CONNECT` | `FD_WRITE` |
| `POLL_ERR` | `FD_CLOSE` | `FD_CONNECT` | `FD_CLOSE` |
| `POLL_HUP`/`POLL_RDHUP` | `FD_CLOSE` | `FD_CONNECT` | `FD_CLOSE` |

Bits combine in one result. A listener's readable queue is therefore never
reported as ordinary data, and a connecting socket's writable/error state is
reported as completion of the connection attempt. The lifecycle role comes
from the socket owner at the projection call; it is not duplicated here.

## 3 Tests

- listener, connecting, and connected projections cover each event class;
- combined read/write/urgent/close readiness preserves every corresponding
  event bit;
- empty readiness produces no event;
- a positive-control test proves the harness fails when the input readiness bit
  is changed.
