# Windows NT wait deregistration

Status: FROZEN
Date: 2026-08-31

`RtlDeregisterWait` is exposed as a native NT thread-pool boundary. A null or
unknown wait object returns `STATUS_INVALID_HANDLE`; the adapter never treats
an arbitrary userspace pointer as a valid registration and never mutates Linux
scheduler state. Full callback registration and completion-wait ownership
will use the same native wait lifecycle when that graph surface is required.

Linux wait and scheduler behavior is unchanged.
