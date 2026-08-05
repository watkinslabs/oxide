# B1769 — scheduling while atomic IRQ fault

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 040167850, c73b49d27 | DEFECT | high | Root-cause and fix B1768's serial-triggered schedule attempt with the softirq preempt-count field set. | `schedule()` now follows Linux's recovery rule on a task stack; per-handler softirq accounting restores the entry count; an IRQ-stack request is deferred through the current task's reschedule flag instead of being dropped or saving the shared stack. Deterministic positive controls fail when count repair or the deferred handoff is removed. Final both-arch feature/frame/stack/IRQ gates and boot smoke passed, and the invalid-DNS x86 serial regression passed without a kernel-fault signature. | B1857-irq-softirq-schedule-fault |
