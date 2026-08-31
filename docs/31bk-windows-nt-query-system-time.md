# Windows NT Query System Time

Status: FROZEN

Date: 2026-08-31

## Contract

Oxide implements the 64-bit `NtQuerySystemTime` export as selector 116. It
converts the kernel's canonical realtime nanoseconds to a Windows FILETIME
count (100-nanosecond intervals since 1601) and writes the result through
the validated user pointer.

The NT personality boundary rejects a null or invalid output pointer; Linux
clock structures are not exposed directly.
