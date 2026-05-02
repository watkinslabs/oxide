# 41 Debug Flags Catalog — v2 deferred entries

Carried at freeze 2026-05-02.

## Per-feature build matrix in CI

v1 lean = yes; nightly job builds every `debug-*` individually to catch bit rot. Cheap.

## Run-time toggle for `debug-*` flags

No. Build-time only — defeats the zero-cost-when-off rule otherwise.
