# 07 Toolchain + Targets — v2 deferred entries

Carried from `docs/07-toolchain-and-targets.md` at freeze 2026-05-02 per `02§9.8`.

## AVX/SSE in kernel hot paths

`memcpy`/checksum/etc. could win from AVX2/AVX-512. v1 = no per `14§7` (save-on-every-entry cost dominates). Revisit if a measured hot path shows >10% wall-clock loss attributable to scalar-only and FPU save cost is amortizable.

## Stack canaries

v1 = `+stack-protector=strong` kernel default ON; `+nostack-protect` cfg flag for hot paths if benchmark shows real cost. v1 must provide `__stack_chk_fail`/`__stack_chk_guard`. v2 considers full stack-clash protection via `-fstack-clash-protection`-equivalent.

## aarch64 `code-model`

Not in target JSON for v1. PC-relative ±2 GiB suffices; documented in linker script. Revisit if kernel mapping crosses 2 GiB.

## Hosted test pattern

`[target.'cfg(test)']` to host triple. Pattern lives in `42` test-strategy spec. Tracked here so v2 doesn't reinvent it.

## Upstreaming custom targets to rustc

`*-unknown-oxide-kernel`: after v1 + 2 years of ABI stability. Userspace `*-unknown-oxide`: only when v2 wants a distinct userspace ABI per `29a§2`.
