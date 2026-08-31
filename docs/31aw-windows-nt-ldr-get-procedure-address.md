# Windows NT LdrGetProcedureAddress

Status: FROZEN

Date: 2026-08-31

## Contract

`LdrGetProcedureAddress` accepts a loaded module base, an optional
`ANSI_STRING` name or ordinal, and an output procedure pointer. Wine validates
the module's export directory, resolves forwarded exports, and returns
`STATUS_PROCEDURE_NOT_FOUND` when the requested symbol is absent.

Oxide exposes the native 64-bit ABI as selector 100. The process-local module
registry and export-directory lookup are not yet published to the NT syscall
adapter, so valid NT callers currently receive `STATUS_NOT_IMPLEMENTED`
instead of a fabricated address. Invalid/non-NT calls remain parameter
failures, and Linux loader state is not consulted or changed.
