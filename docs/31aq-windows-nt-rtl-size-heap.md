# Windows NT `RtlSizeHeap`

FROZEN 2026-09-07. Dep:`31r`.

`RtlSizeHeap` reads the block header of the allocation and returns the size
that was requested: block bytes less the header and the unused tail. A large
allocation reports its recorded data size. An invalid, unaligned, already-freed
or foreign pointer returns the Windows failure sentinel. The query shares the
same allocation namespace as `RtlAllocateHeap`, `RtlFreeHeap`, and
`RtlReAllocateHeap`.
