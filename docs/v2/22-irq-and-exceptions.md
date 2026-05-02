# 22 IRQ + Exceptions — v2 deferred entries

Carried from `docs/22-irq-and-exceptions.md` at freeze 2026-05-02.

## IRQ remapping (Intel VT-d / arm SMMU IRQ routing)

IOMMU-protected MSI routing. Deferred to v1.x.

## Per-CPU softirq priorities

v1 copies Linux ordering. Listed here to record the decision and the alternative (custom priority scheme) being declined for v1.

## Threaded IRQs as default

Linux makes them opt-in. v1 lean = handler-by-handler choice; no global default. v2 may revisit if pre-emption latency budgets demand it.
