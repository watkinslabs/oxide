# Windows NT LdrSetDllDirectory

Status: FROZEN

Date: 2026-08-31

## Contract

`LdrSetDllDirectory` replaces the process-local DLL-directory override with
the UTF-16 contents of its input `UNICODE_STRING`; a null buffer clears the
override. Oxide stores the bytes on the NT `ThreadGroup`, so NT threads share
the state while separate processes do not. Invalid descriptor, length, or
buffer shapes return `STATUS_INVALID_PARAMETER`.

`LdrGetDllDirectory` reads this same state and reports the required terminating
NUL using Wine-compatible `UNICODE_STRING` semantics. The implementation is
reachable only through the native 64-bit NT path and never modifies Linux
loader environment state.
