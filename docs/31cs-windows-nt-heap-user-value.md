# Windows NT heap user values

FROZEN 2026-09-07. Dep:`31r`.

The process heap records `(allocation address, user flags, user value)` in
heap-owned state for allocations requested with `HEAP_ADD_USER_INFO`. Free
removes the record and reallocate moves it to the new allocation address while
preserving the value. Other allocations acquire no record, so the cost is
proportional to the allocations that asked for one, not to the live block
count.

`RtlSetUserValueHeap` updates only an existing record and returns false for an
unknown allocation or an allocation without user info. `RtlGetUserInfoHeap`
writes the stored value and user flags through uaccess. The record is auxiliary
metadata for the allocation and is removed with it, so stale user values cannot
survive a free.
