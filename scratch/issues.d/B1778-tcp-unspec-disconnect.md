| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 4dddca0e0 | DEFECT | low | `connect(AF_UNSPEC)` on a fresh TCP socket returned EINVAL instead of treating TCP_CLOSE as a successful disconnect no-op. | `TcpInit` now has an explicit disconnect case; kernel-target regression test covers it; `cargo check -p net`. Curated row to move after merge. | B1778-tcp-unspec-disconnect |
