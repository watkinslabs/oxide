# B1768 — resolved stub DNS serial probe

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 068551621, dcf0e7dbf | DEFECT | high | B1737's remaining systemd-resolved stub DNS failure. | Serial-only x86 query `getent hosts one.one.one.one` returned public resolver answers on current main, after B1731's loopback-bind fix and B1761's packet-info fix. | B1768 |
| IN-PROGRESS B1857-irq-softirq-schedule-fault | DEFECT | high | A normal serial-console interaction triggers repeated `[BUG] scheduling while atomic: preempt_count=0000000000000100 in_interrupt=1` reports, then the boot harness declares the guest dead. This is independent of DNS: the resolver query succeeded four times before the first fault. | B1768 serial-only x86 boot at guest t=56.298–56.307, after `getent hosts one.one.one.one` returned two public IPv6 answers per query. | B1857-irq-softirq-schedule-fault |
