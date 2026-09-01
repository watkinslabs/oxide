# Windows NT LdrGetProcedureAddress

Status: FROZEN

Date: 2026-08-31

## Contract

`LdrGetProcedureAddress` accepts a loaded module base, an optional
`ANSI_STRING` name or ordinal, and an output procedure pointer. Wine validates
the module's export directory, resolves forwarded exports, and returns
`STATUS_PROCEDURE_NOT_FOUND` when the requested symbol is absent.

Oxide exposes the native 64-bit ABI as selector 100. For the kernel-provided
synthetic ntdll page, the NT syscall adapter validates the loaded module and
`ANSI_STRING`, then resolves exact named exports from the native runtime
catalog. Ordinals and exports from mapped PE modules remain unsupported and
return `STATUS_PROCEDURE_NOT_FOUND` or `STATUS_INVALID_PARAMETER` as
appropriate; Linux loader state is not consulted or changed.
