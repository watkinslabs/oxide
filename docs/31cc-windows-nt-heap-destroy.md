# Windows NT heap destruction

FROZEN 2026-09-07. Dep:`31r`.

`RtlDestroyHeap` preserves Wine/Windows return semantics for the canonical
process heap: destroying handle `1` returns that handle because the process
heap remains owned by the process, and its regions are released with the
address space. Unknown handles are returned unchanged, matching the
invalid-handle path without freeing arbitrary virtual memory.
