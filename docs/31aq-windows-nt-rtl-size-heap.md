# Windows NT `RtlSizeHeap`

Status: FROZEN
Frozen: 2026-08-31

`RtlSizeHeap` queries the VMM-backed allocation extent owned by the native NT
heap adapter. A valid allocation returns its mapped extent size; an invalid or
unmapped pointer returns the Windows failure sentinel. The query shares the
same allocation namespace as `RtlAllocateHeap`, `RtlFreeHeap`, and
`RtlReAllocateHeap`.
