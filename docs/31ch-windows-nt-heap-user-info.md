# Windows NT heap user information

Status: FROZEN
Date: 2026-08-31

`RtlGetUserInfoHeap` validates a pointer against the canonical VMM-backed heap
and returns zero user metadata because allocation user-info storage is not yet
part of the heap record. Invalid heap, output, or allocation pointers return
failure without accepting arbitrary memory.
