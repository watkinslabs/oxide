# Windows NT heap destruction

Status: FROZEN
Date: 2026-08-31

`RtlDestroyHeap` preserves Wine/Windows return semantics for the initial
canonical process heap: destroying handle `1` returns that handle because the
process heap remains owned by the process. Unknown handles are returned
unchanged, matching the invalid-handle path without freeing arbitrary virtual
memory.
