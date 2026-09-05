# Windows NT Query System Information

Status: FROZEN

Date: 2026-08-31

## Contract

Oxide implements the 64-bit `NtQuerySystemInformation` export as selector
115 for `SystemBasicInformation` (class 0) and the native Wine version record
(class 1000). The basic adapter reports the native page size, 64-KiB
allocation granularity, user address bounds, processor affinity mask, and
processor count using Oxide's HAL and CPU state.

Class 1000 returns four NUL-terminated fields: the native NTDLL version,
native build identity, canonical host system name, and canonical host release.
The record is bounded by the caller's output length and reports its exact byte
length through `ReturnLength`.

The information buffer must be the Windows 64-bit basic-information size for
class 0. Class 1000 requires a buffer at least as large as its record. Other
information classes return `STATUS_INVALID_INFO_CLASS`; Linux `/proc` data and
internal kernel structures are not exposed through this boundary.
