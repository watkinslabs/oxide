# Windows NT process heaps

FROZEN 2026-09-07. Dep:`31r`.

`RtlGetProcessHeaps` reports the canonical process heap and writes handle `1`
when the caller supplies capacity. A zero-capacity query reports the required
count without writing; invalid output storage reports failure. The adapter
does not create a parallel heap registry.
