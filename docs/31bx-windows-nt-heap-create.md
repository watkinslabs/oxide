# Windows NT heap creation

Status: FROZEN
Date: 2026-08-31

`RtlCreateHeap` is exposed through the native NT personality and returns the
process heap token consumed by the existing VMM-backed heap adapter. Heap
flags, placement, sizing, lock, and parameter arguments remain part of the
ABI and are accepted by the personality boundary; allocations use native
Linux-derived virtual-memory primitives through the common heap owner.

The initial implementation intentionally keeps one process heap extent
namespace so `RtlAllocateHeap`, `RtlFreeHeap`, and `RtlReAllocateHeap` cannot
disagree about ownership. Separate heap namespaces require a canonical heap
object table before they can be added safely. Linux allocation behavior is
unchanged.
