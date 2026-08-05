# D512 — fold fixed lane drops

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| IN-PROGRESS D512-fold-fixed-lane-drops | INFRA | med | Seventeen lane drop files contain no live rows, leaving already-fixed work outside `scratch/fixed-issues.md` and making the rendered ledger report closed work as uncurated state. | `scratch/issues.d`: 17 files have one or more `FIXED` rows and zero `OPEN`/`IN-PROGRESS` rows; several duplicate rows already archived by later reconciliation lanes. | D512-fold-fixed-lane-drops |
