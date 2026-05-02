# 04 Performance + Debug + Logging — v2 deferred entries

Carried from `docs/04-performance.md` at freeze 2026-05-02 per `02§9.8`.

## vDSO `clock_gettime`+`getcpu`

v1 = day-1 (small impl; large syscall savings). v2 may extend to other vDSO entry points (`gettimeofday` already implied; `time`, `clock_getres`, fast `getpid` candidates) once measured benefit justifies the surface.

## Format-string interning

v1 = defmt-style linker section (zero runtime cost; custom userspace decoder). v2 considers tracing-style runtime registry only if dynamic loadable modules need to register format strings post-boot.

## Bench harness

v1 = criterion for policy + custom cycle-accurate (`rdtsc` / `cntvct_el0`) for kernel hot paths. v2 considers replacing criterion with full custom harness if multi-arch criterion overhead distorts noise floor.

## `tracing` ecosystem types

v1 = own minimal types; smaller surface. Port to/from `tracing` happens at userspace decoder, not in-kernel. v2 reconsiders if userspace tooling demand grows.

## PerCpu ergonomics

Settled in `06§4` as HAL implementation detail. Listed here only so the v2-deferred-list is exhaustive vs the original OQ.
