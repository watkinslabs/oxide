# Windows NT heap user values

Status: FROZEN
Date: 2026-08-31

The native process heap records `(allocation address, user flags, user value)`
in process-owned NT heap state. Allocations requested with
`HEAP_ADD_USER_INFO` create a record; free removes it and reallocate moves it
to the new allocation address while preserving the value. Other allocations
do not acquire user metadata.

`RtlSetUserValueHeap` updates only an existing user-info record and returns
false for an unknown allocation or an allocation without user info.
`RtlGetUserInfoHeap` writes the stored value and user flags through uaccess.
The record is auxiliary metadata for the canonical VMM allocation and is
removed with that allocation, so stale user values cannot survive a free.
