# Windows NT time-to-seconds conversion

FROZEN 2026-08-31. Dep: 01,02,31f3,52,53. Provides the native `RtlTimeToSecondsSince1970` export required by the installed 64-bit Wine Notepad graph.

The bridge converts 100-nanosecond Windows epoch ticks to an unsigned 32-bit Unix-seconds value, rejecting pre-epoch and overflow results or invalid user pointers.
