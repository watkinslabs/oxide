# 38 Error Handling — v2 deferred entries

Carried from `docs/38-error-handling.md` at freeze 2026-05-02 per `02§9.8`.

## Kdump-style crash dumps to disk

Requires functional disk + filesystem in panic path; nontrivial. Defer to v1.x. v2 considers a minimal raw-block crash dump format (kdump-equivalent) once block + early-init paths are stable.

## Kernel-panic netconsole

UDP-over-MAC dump on panic. Useful for headless boxes. Deferred to v1.x; v2 considers a structured (not raw-text) on-wire format.

## Per-task soft-oops to userspace

`prctl(PR_SET_DEATHSIG)`-style mechanism for delivering backtrace + register state to a parent on task death. Deferred.
