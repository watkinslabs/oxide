# B1654 — AF_UNIX MSG_OOB

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| OPEN | med | `git stash` is shared across ALL worktrees of this clone, so two lanes stashing/popping concurrently swap trees: B1654's stash was popped into another lane's worktree and a raw-IP lane's WIP landed in B1654's. Recovered via `git fsck` dangling commits + `git stash store`. Lanes must never use `git stash` on this box; commit temporarily on the lane branch instead. | Observed 2026-08-01: `git stash pop` in the B1654 worktree restored 16 unrelated `raw4`/`sol_ip` files and dropped B1654's tracked edits. Damage still visible in `git stash list`. | — |
| OPEN | low | `mm` test `swap::tests::final_swap_reference_reclaims_zram_slot` fails. Pre-existing on `main`, unrelated to any net change. | Confirmed on a clean `origin/main` worktree during B1654; `cargo run -p xtask -- test` exits 101 on it alone. | — |
| OPEN | low | AF_UNIX `poll` reports `EPOLLIN` while the only thing queued is a spent out-of-band record, which delivers no bytes — a read then returns nothing and blocks. Faithful to the reference (its receive queue is non-empty), and deliberately kept, but it is a readiness report a caller cannot act on. | B1654. `SIOCINQ` discounts the record and answers 0 in the same state; `net::unix_sock::tests::oob::queued_byte_count_discounts_the_spent_record`. | — |
