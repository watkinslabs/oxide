# 23 Time — v2 deferred entries

Carried from `docs/23-time.md` at freeze 2026-05-02.

## Per-CPU TSC offset rendezvous

Cores boot at different cycle counts; synchronized at boot via cross-CPU rendezvous. Spec'd here to v1; implementation detail in HAL.

## TAI / leap seconds (`CLOCK_TAI`)

Ship as separate clock from REALTIME. v1 lean = yes; cheap.

## Time namespaces (`CLONE_NEWTIME`)

Per-namespace offset on `CLOCK_MONOTONIC`. v1.

## vDSO `getcpu` cache

`cpu_id` stashed in `gs:[…]` / `tpidr_el0`-relative slot; vDSO reads it. v1.

## Drift-correction algorithm

PI controller deferred; v1 ships proportional-only. v2 considers PI/PID once jitter measurements warrant.
