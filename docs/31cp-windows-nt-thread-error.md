# Windows NT thread error state

Status: FROZEN
Date: 2026-08-31

The x86-64 TEB owns `LastErrorValue` at offset `0x68`. Native RTL services
write and read that field through the current NT thread's published TEB
address. `RtlSetLastWin32Error` and `RtlRestoreLastWin32Error` return success
after a valid TEB write; `RtlGetLastWin32Error` returns the DWORD value.

The field is initialized to zero by the mapped TEB page. This keeps the
thread-local Windows error contract in the user-visible TEB rather than in a
second kernel-side cache, so direct TEB reads and RTL calls observe one state.
