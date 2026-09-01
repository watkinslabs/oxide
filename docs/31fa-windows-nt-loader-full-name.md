# Windows NT native loader full-name query

FROZEN 2026-08-31. Dep: 01,02,31f9,52,53. Provides `LdrGetDllFullName` for registered 64-bit PE modules.

The query walks the process loader's canonical in-load-order list, copies the selected module's `UNICODE_STRING` with Wine-compatible truncation and termination, and reports `STATUS_BUFFER_TOO_SMALL` when the destination cannot hold the full name.
