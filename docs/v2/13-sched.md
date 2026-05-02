# 13 Sched — v2 deferred entries

Carried from `docs/13-sched.md` at freeze 2026-05-02.

## CFS vs EEVDF

v1 = CFS (oracle simpler). v1.x switches to EEVDF.

## cgroup cpu-controller hierarchy

v1 = flat + cgroup-quota (`cpu.max`) only; no weighted hierarchy. v1.x adds.

## DEADLINE class (EDF + admission control)

v2.

## Per-CPU idle (3-class model)

3-class model retained for v1 (simplicity wins).

## Lock-held-across-switch

Releasing the rq lock before context switch and retaking after opens a window where two CPUs pick the same task. v1 keeps lock-held-across-switch. Listed here as the negative-result decision.

## Load-balance cadence

v1 = 10 ms; tunable via sysctl-equivalent. v2 may auto-tune.
