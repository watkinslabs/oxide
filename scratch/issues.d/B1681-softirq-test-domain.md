# B1681 — softirq hosted tests share one processor state

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1681 | med | `softirq` hosted tests took no serialization at all while every one of them mutates `PENDING[0]`, `PROCESS_PENDING` and `HANDLERS[]` — the processor's ONE softirq state, which a hosted test binary models exactly one of. Run in parallel they clear each other's pending bits and overwrite each other's handlers; the loser reports a handler that "never ran" or a bit that "stayed set" (`raise_then_run_invokes_handler` was the observed casualty in a workspace run). Resetting the statics on entry only ordered the damage. | `cargo test -p softirq` 29/30 clean before, 30/30 after; combined with `fbcon` (B1682) the pair was 8/30 before. | — |
