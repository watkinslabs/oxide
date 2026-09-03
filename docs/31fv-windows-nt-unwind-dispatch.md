# Windows NT builtin unwind dispatch validation

FROZEN 2026-09-03. Dep:`31fp`,`31fu`,`31ft`,`31h`,`52`,`53`. Provides: the
typed selector boundary before Wine builtin unwind execution.

## 1

The Unix-call shim reads the request's 32-bit unwind selector before reading
the nested dispatcher and context pointers. Only the four defined virtual
unwind flag combinations are admitted: no-handler, exception-handler,
termination-handler, and chained-record flags. Unknown bits fail with
`STATUS_INVALID_PARAMETER`.

Pointer validation and DWARF execution remain separate owners. A valid request
continues to the loaded-image runtime owner; this validator does not reinterpret
the dispatcher or context layouts.

## 2

Hosted tests exercise the selector decision, including a positive control for
unknown bits. Target checks compile the kernel path. The runtime owner must
still connect the selector, published `.eh_frame`, FDE lookup, CFA evaluator,
and fault-aware user-memory reader before builtin unwinding is complete.
