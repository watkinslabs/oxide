# Windows NT wait registration

Status: FROZEN
Date: 2026-08-31

The native wait boundary validates an NT-process waitable handle and callback,
allocates a process-scoped registration token, and stores the callback context,
timeout, and execution flags. `RtlDeregisterWait` removes only a live token and
returns `STATUS_INVALID_HANDLE` for stale or foreign values. Callback delivery
and timeout scheduling remain part of the native wait-queue execution contract.
