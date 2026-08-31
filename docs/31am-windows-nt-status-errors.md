# Windows NT status error translation

Status: FROZEN
Frozen: 2026-08-31

The native NTDLL surface exposes `RtlNtStatusToDosError`. It preserves
success and customer-status values, normalizes equivalent failure classes,
maps the common NT statuses used by the runtime to Win32 error values, and
returns `ERROR_MR_MID_NOT_FOUND` for unknown statuses. It has no Linux
syscall side effects and does not modify the Linux personality’s errno state.

The native RTL surface also provides `RtlUniform`, using the Wine-compatible
32-bit Lehmer/LCG transition and updating the caller’s seed through the
user-access boundary.
