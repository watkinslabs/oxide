# Windows NT RTL text detection

Status: FROZEN
Frozen: 2026-08-31

The native x86-64 NTDLL surface exposes `RtlIsTextUnicode`. It reads at
most the first 256 UTF-16 code units, applies Wine-compatible signature,
statistics, null-byte, control, reverse-control, and odd-length tests, and
returns the resulting Windows boolean and optional test mask. User buffers
and the optional mask are accessed only through the user-access boundary.

The heuristic is intentionally a text guess, not a Unicode conversion or a
filesystem operation; Linux personality syscall behavior is unchanged.
