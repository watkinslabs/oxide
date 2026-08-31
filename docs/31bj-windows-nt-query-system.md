# Windows NT Query System Information

Status: FROZEN

Date: 2026-08-31

## Contract

Oxide implements the 64-bit `NtQuerySystemInformation` export as selector
115 for `SystemBasicInformation` (class 0). The adapter reports the native
page size, 64-KiB allocation granularity, user address bounds, processor
affinity mask, and processor count using Oxide's HAL and CPU state.

The information buffer must be the Windows 64-bit basic-information size,
and the return-length pointer is honored. Other information classes return
`STATUS_INVALID_INFO_CLASS`; Linux `/proc` data and internal kernel
structures are not exposed through this boundary.
