# Windows NT heap creation

FROZEN 2026-09-07. Dep:`31r`.

`RtlCreateHeap` is exposed through the native NT personality and returns the
process heap token consumed by the heap owner (`31r`). Heap flags, placement,
sizing, lock, and parameter arguments remain part of the ABI and are accepted
at the personality boundary.

One process heap namespace is kept so `RtlAllocateHeap`, `RtlFreeHeap`, and
`RtlReAllocateHeap` cannot disagree about ownership; the heap reserves its own
regions and grows by reserving more, so a created heap costs no address space
until it is used. Separate heap namespaces require a canonical heap object
table before they can be added safely. Linux allocation behavior is unchanged.
