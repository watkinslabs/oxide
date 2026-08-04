# D477 — Fold merged UART fix

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 62db4ad49 | INFRA | low | Folded the merged B1758 UART transaction fix into the canonical ledger, retiring its live rows and correcting the stale duplicate archive row. | PR #4523 merged; archive retains one fixed row with hosted and serial-only smoke evidence. | D477-ledger-fold-uart-fix |
