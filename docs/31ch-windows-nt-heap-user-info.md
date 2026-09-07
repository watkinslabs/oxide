# Windows NT heap user information

FROZEN 2026-09-07. Dep:`31r`,`31cs`.

`RtlGetUserInfoHeap` validates a pointer against the process heap and writes
the stored user value and user flags of that allocation (`31cs`). An allocation
made without `HEAP_ADD_USER_INFO` has no record and reports failure. Invalid
heap, output, or allocation pointers return failure without accepting arbitrary
memory.
