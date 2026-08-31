# Windows native performance counter

FROZEN 2026-08-31. Dep:`01`,`02`,`31h`,`52`,`53`. Provides: monotonic high-resolution counter services used by Wine runtime code.

## Contract

- `RtlQueryPerformanceCounter` and `RtlQueryPerformanceFrequency` are append-only NT services `65` and `66`.
- Both accept a pointer to a 64-bit `LARGE_INTEGER` and return a Windows boolean success value (`1`); invalid NT-personality or user pointers return `STATUS_INVALID_PARAMETER`.
- The counter is the canonical Oxide monotonic clock converted from nanoseconds to 100-nanosecond ticks. Its fixed frequency is `10,000,000` ticks per second, matching Wine’s NTDLL contract.
- Linux clock behavior and syscall numbering are unchanged.

## Tests

- selector and native-export resolution tests cover both routines;
- target compilation covers the usercopy adapter on x86_64 and aarch64;
- the installed Wine Notepad graph reports the next unresolved import rather than silently loading Wine `ntdll.dll`.
