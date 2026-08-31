# Windows NT Debug UI Object

Status: FROZEN

Date: 2026-08-31

## Contract

`DbgUiGetThreadDebugObject` is a zero-argument native NTDLL helper that
returns the current thread's debug-object handle. Wine implements it by
reading `TEB.DbgSsReserved[1]`.

Oxide's foundation runtime has no debugger attachment or NT debug-object
store yet. Until that subsystem is implemented, an NT thread is unconnected
and the helper returns the Windows null-handle value (`0`). Linux tasks are
never given access to this NT-only route. The native x64 stub is unary and is
resolved by the PE loader as selector 97.
