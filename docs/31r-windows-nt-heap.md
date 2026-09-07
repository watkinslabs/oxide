# Windows native heap boundary

FROZEN 2026-09-07. Dep:`31d`,`31h`,`52`,`53`. Provides: the native process heap that sub-allocates blocks inside reserved regions.

## 1 Contract

- `RtlAllocateHeap` and `RtlFreeHeap` are exposed by the native NTDLL bootstrap as tagged NT entries `25` and `26`.
- The Windows x64 register order is preserved by the same six-argument thunk used by the native NT calls: heap, flags, size/base.
- A heap owns reserved regions; a region is committed a granule at a time and carved into blocks. An allocation costs no address-space operation unless the heap has to grow.
- Every returned data pointer is 16-byte aligned and preceded by an 8-byte block header carrying block size, unused tail, owning region and block type.
- Block sizes are exact: `RtlSizeHeap` reports the requested size, not a mapped extent.
- A free coalesces with its free neighbours. A grown region that becomes entirely free is released; the first region is retained.
- A request whose block would exceed the header's size field takes its own reservation and is released on free.
- `HEAP_ZERO_MEMORY` zeroes the served body explicitly; a resize zeroes only the bytes it adds.
- Heap handles and flags remain part of the ABI: the canonical process heap is handle `1` and every heap call resolves to it.
- Linux ELF allocation and the Linux syscall selector table are unchanged.

## 2 Wine relationship

Wine's `kernel32.dll` forwards `HeapAlloc` and `HeapFree` to NTDLL heap exports. The native implementation therefore owns block policy while the Wine-derived Win32 DLLs retain their existing API surface.

## 3 Structure

- Block policy (`52§5`) is an address-space-free crate: geometry, free-block search, split, coalesce, growth, large blocks.
- The free index is heap-owned state, not links inside the served memory, so a process cannot corrupt its own heap metadata.
- The ABI shim supplies reserve/commit/release and user-memory access; it holds no block state.

## 4 Tests

- selectors `25` and `26` decode without argument reordering;
- the native runtime resolves `RtlAllocateHeap` and `RtlFreeHeap`;
- data pointers are block-aligned and reported sizes are exact;
- N small allocate/free pairs cost a constant number of address-space operations, with the page-per-allocation shape as the failing control;
- coalescing, in-place resize, move-and-copy, zeroing and region release are driven against a counting address space;
- Notepad's transitive Wine catalog audit remains in the normal compatibility target;
- both kernel architectures continue to type-check the expanded selector table.
