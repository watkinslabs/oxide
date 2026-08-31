# Windows NT Unbiased Interrupt Time

Status: FROZEN

Date: 2026-08-31

## Contract

The native NTDLL `RtlQueryUnbiasedInterruptTime` export writes the current
unbiased interrupt time to its non-null `ULONGLONG *` argument and returns the
Windows `BOOL` value `TRUE`. The value is represented in 100-nanosecond ticks.

The implementation translates the existing kernel monotonic timekeeper,
including its suspend-accounting rules, rather than changing Linux clock
behavior or exposing a host-specific clock directly. Invalid pointers,
non-NT callers, and absent current threads return `FALSE`.

The export is included in the native 64-bit NTDLL stub page and is resolved by
the PE loader as selector 96. The user pointer is written through the normal
uaccess boundary.
