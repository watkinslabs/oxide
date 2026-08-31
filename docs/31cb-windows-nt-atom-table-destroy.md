# Windows NT atom-table destruction

Status: FROZEN
Date: 2026-08-31

`RtlDestroyAtomTable` validates the native process-local atom-table token,
clears all string atoms, and retires the table. A stale token or repeated
destruction returns `STATUS_INVALID_PARAMETER`; the implementation does not
touch Linux's global atom namespace.

The table lifecycle is shared by Windows clone-threads through the native
thread-group state and is fresh for a new process group.
