# B1763 — rtnetlink address-attribute ledger reconciliation

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1763 | COVERAGE | low | C272 kept two open rows for B1748's already-merged address-record fix, obscuring the still-open work on deleting the duplicate record type and adding the remaining address attributes. | `4d0724171` is an ancestor of fresh main and its focused tests cover the exact old defects; the duplicate rows moved to `scratch/fixed-issues.md`. | B1763 |
