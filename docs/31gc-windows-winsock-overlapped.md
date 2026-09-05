# Windows Winsock overlapped completion

FROZEN 2026-09-04. Dep:`01`,`02`,`25`,`31aa`,`31gb`,`52`,`53`. Provides: per-operation Winsock completion state.

## 1 Contract

- Each submitted operation starts with `STATUS_PENDING`; a pending nonblocking result is `WSA_IO_INCOMPLETE`.
- Completion publishes transferred bytes and flags before the terminal status with release ordering. Readers acquire the status before reading the payload.
- Exactly one terminal completion wins. A duplicate completion, a pending terminal status, and rearming a live operation are rejected.
- Cancellation is a terminal `STATUS_CANCELLED` and reports `WSA_OPERATION_ABORTED`. A completed record may be explicitly rearmed for a later operation.
- Linux `InetSocket` readiness and `SocketError` remain the sole sources of readiness and transport error observations. The completion record contains no shadow socket state.
- Linux errno and NT status translations use one Winsock result namespace, including reset, refused, unreachable, timeout, buffer, and cancellation outcomes.

## 2 Ownership

| Responsibility | Owner |
|---|---|
| readiness and pending socket errors | `net::sock::InetSocket` and `SocketError` |
| per-operation pending/terminal publication | `net::windows_async::Overlapped` |
| Linux errno and NT status result mapping | `net::windows_async` |
| wait/event and user-memory ABI | NT/Winsock adapter |

## 3 Tests

- pending, successful payload publication, duplicate completion, and forbidden pending status;
- cancellation, explicit rearm, and refusal to rearm a live operation;
- equivalent Linux errno and NT status mappings;
- unknown failure cannot be reported as success.
