# Windows NT process heaps

Status: FROZEN
Date: 2026-08-31

`RtlGetProcessHeaps` reports the canonical process heap and writes handle `1`
when the caller supplies capacity. A zero-capacity query reports the required
count without writing; invalid output storage reports failure. The adapter
does not create a parallel heap registry.
