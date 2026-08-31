# Windows native heap boundary

FROZEN 2026-08-31. Dep:`31d`,`31h`,`52`,`53`. Provides: the first VMM-backed native heap primitives used by the Wine-derived runtime.

## 1 Contract

- `RtlAllocateHeap` and `RtlFreeHeap` are exposed by the native NTDLL bootstrap as tagged NT entries `25` and `26`.
- The Windows x64 register order is preserved by the same six-argument thunk used by the native NT calls: heap, flags, size/base.
- Allocation requests are rounded up to pages and use private read/write VMM mappings.
- A successful free releases the exact VMM extent containing the returned allocation; invalid or unmapped pointers return the Windows failure value.
- Heap handles and flags remain part of the ABI but are not yet a multi-heap policy: the initial process heap is the common process address space.
- Linux ELF allocation and the Linux syscall selector table are unchanged.

## 2 Wine relationship

Wine's `kernel32.dll` forwards `HeapAlloc` and `HeapFree` to NTDLL heap exports. The native implementation therefore owns the allocation extent while the Wine-derived Win32 DLLs retain their existing API surface.

## 3 Tests

- selectors `25` and `26` decode without argument reordering;
- the native runtime resolves `RtlAllocateHeap` and `RtlFreeHeap`;
- allocation and exact release use the common VMM;
- Notepad's transitive Wine catalog audit remains in the normal compatibility target;
- both kernel architectures continue to type-check the expanded selector table.
