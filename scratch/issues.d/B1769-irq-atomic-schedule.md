# B1769 — scheduling while atomic IRQ fault

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| IN-PROGRESS B1857-irq-softirq-schedule-fault | DEFECT | high | Root-cause and fix B1768's serial-triggered schedule attempt with the softirq preempt-count field set. | Current main serial boot emits `[BUG] scheduling while atomic: preempt_count=0000000000000100 in_interrupt=1` repeatedly after a successful guest resolver query. B1769 makes that report name the direct `schedule()` caller on the next reproduction. | B1857-irq-softirq-schedule-fault |
