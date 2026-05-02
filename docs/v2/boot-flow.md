# Boot Flow — v2 deferred entries

Carried at freeze 2026-05-02.

## KASLR enable point

v1.x; between memmap parse and kernel relocation, or pre-smp_init. Lean = pre-relocation.

## Initial driver-probe parallelism

v1 = serial in `linkme` order (deterministic). v1.x considers CPU-bound parallel.
