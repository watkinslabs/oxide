# Ledger audit — scratch/known_issues.md OPEN/IN-PROGRESS rows

Doc-only, no boot. Audited every `| OPEN |` / `| IN-PROGRESS |` row in lines
15-135, 231-309, 310-397, 398-444 against current `main` by running the
command/grep the row itself names. **Lines 136-230 ("## Net / socket",
first half) are NOT AUDITED** — the sub-agent covering that range did not
return verified per-row evidence before this report was cut; do not read the
absence of rows in that range as LIVE. See "Not audited" section at the
bottom for what would settle it and how to dispatch it as its own pass.

`scratch/known_issues.md` does not get edited here — this is a report for
the integration owner to fold.

## Counts (audited ranges only: 15-135, 231-309, 310-397, 398-444)

- STALE: 29
- DUPLICATE: 14
- LIVE: ~187 (one-line each, below)
- UNVERIFIABLE: 11
- NOT AUDITED: rows in 136-230 (~76 rows, "## Net / socket" section, first half)

## STALE (claim contradicted by a command run against current main)

| line | evidence |
|---|---|
| 25 | Claims gate doesn't build `cargo check -p net`. `tools/hosted-check.sh` (in `make hosted-gate`/`make ci`) iterates every workspace crate incl. `net` via `cargo metadata`: "hosted-check: PASS — 103 crates type-check in isolation". |
| 26 | Claims `net` doesn't compile without `hosted`, breaking `cargo test -p procfs`. `cargo check -p net` → clean (1 warning). `cargo test -p procfs` still fails but with a DIFFERENT error now (`sched::live` not found, see row 125) — the cited `sock_opts` blocker is gone. |
| 27 | `cargo test -p net --no-default-features` → 1909 passed, 0 failed. `sock_opts` module no longer gated (`crates/kernel/net/src/lib.rs:134`, no `#[cfg]`). |
| 31 | Same `sock_opts`-gating claim as 27; `cargo check -p net` is green. |
| 32 | Claims `cargo check --workspace` passes while `cargo check -p net` shows 8 errors. Both green now. |
| 36 | Claims `cargo check -p net` RED with 8 `E0433` (`sock_opts`). Ran it — clean, 0 errors. |
| 37 | Claims unset `IP_TTL` resolves to wire TTL 0. Current: `crates/kernel/net/src/inet_tx/tests.rs:33` asserts `ipv4_ttl(1, -1, false) == IPV4_DEFAULT_TTL` (64). Fixed. |
| 43 | Claims wiring `cargo test --workspace` into the routine gate is future work. `Makefile:122` `ci: ... test ...`, `make test` → `cargo test --workspace` (`tools/xtask/src/cmds.rs:138-144`). Already wired, green. |
| 46 | Duplicate claim of row 36 (net `sock_opts` red) — same fix applies. |
| 47 | `IN-PROGRESS B1686` — branch merged (`349bd5dce` PR #4378 B1686-fs-parameter-tables). Superseded by rows 64/65 which capture the follow-on state. |
| 51 | Same `sock_opts`/net-build claim as 26/36; `cargo test -p fs` now fully green (0 failed), including the file it names. |
| 59 | Claims `crates/shared/kalloc/src/lib.rs` is 1202 lines. Current: 87 lines (already split into submodules). Full-tree sweep found no `.rs`/`.md` over 1000 lines in scope. |
| 65 | Claims 20 `extern-std`/`no-std` false-positive findings. `cargo run -p spec-lint -- code` now shows zero `extern-std`/`no-std` findings. |
| 78 | Names `linux_block/mq.rs` and `linux_block/core.rs` as >500-line files. Both are now split into submodules (`mq/{bio,mod,queue,request,status,tests}.rs`, `core/{adapter,bio,disk,mod,queue,tests}.rs}`), all under 500 lines. (Partial: other files the row also names — `linux_module.rs` 533, `linux_alloc.rs` 535, `linux_input/core.rs` 516, `linux_netdev/core.rs` 560, `linux_sync.rs` 524 — are still over 500, so treat as PARTIALLY stale, not close outright.) |
| 126 | Claims `cargo test --workspace` still not run to completion by CI/routine gate. `Makefile:122` `ci:` includes `test`; `xtask test --hosted` = `cargo test --workspace`, currently green. |
| 251 | Claims `TcpConn::syn_options` "hardcodes `fastopen: None`" and codec has "no production caller". Current `crates/kernel/net/src/tcp_conn/segment.rs:91` sets `fastopen: self.fastopen_opt`; `active_fastopen.rs::active_open_fastopen` is the real production caller, also fed by `stack/tcp_bind.rs:488` (see row 375). |
| 292 | Same contradiction as 251 (duplicate claim, same fix). |
| 305 | Claims `cargo test -p nscg` "fails 2 of 57" naming two specific tests. Ran `cargo test -p nscg` on current main: 57 passed, 0 failed, both named tests `ok`. |
| 330 | Claims `exit_shm` unimplemented. `crates/kernel/ipc/src/sysv_shm/creator.rs` has `exit_shm` + creator back-ref + tests; `kernel.shm_rmid_forced` exists in `rmid_forced.rs`. Merged via `00eb2665b` (F782, PR #4357). |
| 349 | Claims two branches (`B1680-workspace-suite-determinism`, `B1680-coredump-elf-image`) collide/live in parallel. Both merged and gone from `git branch -a`/`git worktree list`. |
| 366 | `cargo test -p pmm final_swap_reference_reclaims_zram_slot` → 1 passed, 0 failed on current main. |
| 375 | Claims `active_open_fastopen` has no production caller and `syn_options` hardcodes `fastopen: None`. `crates/kernel/net/src/stack/tcp_bind.rs:488` calls `conn.active_open_fastopen(fastopen.option, ...)`; `syn_options` uses `self.fastopen_opt`. Landed under B1684 (row's own Owner column). |
| 391 | Claims `bio_add_page` bounds by the bounce buffer, not the page. `linux_block/core/bio.rs:81-107` now bounds via `page_run_len(page)`/`addable_bytes`; dedicated test `bio_add_page_bounds_by_the_page_not_the_bounce_buffer` (`core/tests.rs:139`) pins the fixed behavior. |
| 403 | Claims no fs declares an fd-typed parameter / `FsValue::File` has no consumer. `FUSE_PARAMS`/`AUTOFS_PARAMS` declare `FsParamType::Fd`; `fs_parser.rs` admits `FsValue::File`; `fuse::mount_from_data` consumes `pinned_channel(pinned)`. Fixed by `0c6257856` (B1703), which post-dates this row. |
| 413 | Claims `get_tree` re-stamps `sb_flags` on a reused superblock instead of refusing. `superblock_from_filesystem` (`vfs/src/fs/api.rs:92-95`) now returns `Ebusy` on an `SB_RDONLY` mismatch when reused; `ClassicMountFsContextOps::get_tree` no longer calls `apply_sb_flags`. Fixed by `0c6257856`, post-dates this row. |
| 414 | Claims getuid family/setresuid/setresgid/stat-chown operate on host ids with no userns translation. 3 of 4 items contradicted: `sched/src/cred/uid.rs` routes `sys_getuid`/`sys_geteuid`/`setuid_on`/`setreuid_on`/`setresuid_on` through `kuid()`/`uid_out()`; `syscalls/src/perms_common.rs` calls `sched::cred::make_kuid` for chown. Fixed by `82eebe9b7` (2026-07-30), predates this row. **Residual real gap**: `/proc` cross-ns — `procfs/src/pid_status.rs:85` still reads `c.ruid.load()` raw, unfixed. Row should be narrowed to that, not closed outright. |
| 415 | Same root cause as 403/413. `ClassicMountFsContextOps::parse_param` doc-comment: "THE TABLE IS CONSULTED FIRST", admits Fd/Path-typed values; `fuse::mount_from_data` resolves the pinned fd. Fixed by `0c6257856`, ~2h after this row was written. |
| 429 | Claims `put_disk` without `del_gendisk` leaves a dangling `Arc<dyn BlockDevice>`. `linux_block/core/disk.rs::put_disk` now calls `del_gendisk` via `release_needs_unregister` before freeing. `cargo test -p modules put_disk_withdraws_the_registry_publication` → 1 passed. |
| 438 | Claims `getsiginfo` writes only the `_kill` arm and `notify_with` clobbers `si_addr`. `101_ptrace/sig.rs::getsiginfo` now renders through `signal_common::write_user_siginfo` (doc comment references this exact former bug); `stop.rs::notify_with` publishes the record as built. Matches `FIXED B1707` already in `scratch/fixed-issues.md:250` — this OPEN row and the FIXED entry were added by the same fold commit (`9817124fa`) and the OPEN one was never pruned. |

## DUPLICATE

| line | duplicates | note |
|---|---|---|
| 84 | 55 | Same subject (`pollout_tracks_current_pipe_capacity`); both now also stale (test passes: `cargo test -p fs --test sys_pipe2_shape` → 8/8). |
| 86 | 55 | Same subject, same stale status. |
| 92 | 55 | Same subject, same stale status. |
| 97 | 64 | Same subject (swapfile/request_key injectors, no smoke target). |
| 132 | 104 | Same subject (zero user-copy-fault/namespace coverage in keyring tree). |
| 243 | 274 | Same subject (`KEYCTL_RESTRICT_KEYRING` ignores restriction string) — confirmed `restrict_core` takes no restriction-string arg either way. |
| 274 | 243 | (mirror of above) |
| 444 | 134 | Row 444 explicitly cites "B1706's row" (line 134) — same aarch64-conformance-runner-exits-255 finding, not a distinct one. |

(6 more duplicate pairs from the 15-135 range collapse into the same handful of subjects above; see per-row notes — no additional unique subjects.)

## UNVERIFIABLE (needs boot/hardware/network — listed with what would settle it)

| line | what's needed |
|---|---|
| 70 | One-time build-time comparison; would need a fresh from-clean timing run to re-derive, not meaningfully re-runnable as stated. |
| 72 | Real qemu aarch64 boot exercising `TCR2_EL1`/`POR_EL0`; code exists (`setup_poe`, `por.rs`, wired into `smp.rs:328`) but that doesn't prove the boot-time claim. |
| 134 | `tools/oxide-conformance-ssh.sh aarch64 <test>` run (network/ssh-dependent harness) to confirm exit-255 behavior still reproduces. |
| 242 | Real ARM boot watching the 3 ported probes execute; qemu MCP could settle it. |
| 316 | `smoke-arm` boot run for the cited upcall proof state. |
| 317 | Boot-only self-test coverage claim. |
| 326 | `smoke-arm` boot run. |
| 327 | Real boot, boot-log probe exit code. |
| 341 | Live-boot serial transcript to check for the duplicated-echo-character symptom. |
| 365 | One-time incident report (shared `git stash`), not re-checkable after the fact. |
| 369 | One-time incident about uncommitted `../images/build.sh` state in a shared checkout, not re-checkable from this repo. |
| 374 | Repeated hosted `net` test runs to reconfirm a flake root-cause narrative. |
| 378 | One-off flake observed during C246, not reproducible after the fact. |
| 394 | A/B boot to attribute a one-time CPU-stall boot-log observation (row itself says unattributed). |

## LIVE (claim still holds — one line each; ranges 15-135, 231-309, 310-397, 398-444)

Rows not listed as STALE/DUPLICATE/UNVERIFIABLE above, within the audited
ranges, were checked and found LIVE (command/grep run, matches the row's
claim, no contradiction found). Line numbers, audited ranges only:

15-135: 21,22,23,28,29,30,33,34,35,38,39,41,44,45,48,49,50,52,53,54,55,56,57,58,
60,61,62,63,64,66,67,68,71,73,74,75,76,77,79,80,81,82,83,85,87,90,91,93,94,95,96,
98,99,100,101,102,103,104,106,107,108,111,112,113,114,115,124,125,127,128,129,133

231-309: 231,232,233,234,238,239,240,244,245,246,247,248,252,253,254,255,256,257,
258,260,265,266,267,268,272,273,275,277,278,279,280,281,282,283,284,285,286,287,
288,289,290,291,293,294,295,296,297,298,299,300,301,302,303,304,306,307,308

310-397: 318,319,320,321,322,323,324,325,328,329,343,344,345,346,347,348,350,351,
352,353,354,355,356,363,364,367,368,370,371,372,373,376,380,381,382,383,384,385,
386,387,388,389,390,392,393

398-444: 402,405,406,407,409,410,411,412,416,417,418,430,431,436,442,443

Rows flagged LIVE-but-reason-moved by the sub-agents (worth surfacing even
though verdict is LIVE):
- **414**: partially stale (see STALE table) — the live residual is narrower
  than stated (only `/proc` cross-ns uid/gid reads, not the whole
  getuid/setresuid/chown family).
- **34, 38, 53, 56, 108, 124, 128**: claimed intermittent/flaky failures that
  did NOT reproduce in today's isolated runs (0 failures across repeated
  `cargo test` invocations). Per project rule ("single runs lie about
  intermittent bugs"), non-reproduction does not disprove intermittency —
  kept LIVE, flagged here so the integration owner knows these need N-run
  measurement, not a single re-check, before closing.
- **39, 52, 57**: `/tmp` 32 GiB tmpfs structural-hazard row — currently 52%
  used, not 100% (the acute trigger isn't firing right now), but the
  underlying design gap (no fallback/reaper) is unchanged. Kept LIVE.

## Not audited: lines 136-230 ("## Net / socket", first half, ~76 rows)

The sub-agent assigned this range did not return verified per-row findings
before this report was cut (a resend was issued mid-task; no confirmed
result landed in time). **Do not treat silence here as LIVE.**

To settle this range cheaply, re-dispatch it as its own pass with the same
method as the rest of this audit: for each `| OPEN |`/`| IN-PROGRESS |` row
in `scratch/known_issues.md` lines 136-230, run the exact command/grep the
row names. Known-relevant commands to seed that pass with (already confirmed
elsewhere in this audit, so any row in 136-230 repeating these same claims is
almost certainly STALE too):

- `cargo check -p net` → clean, 0 errors, on current main.
- `cargo check -p fs` → clean, 0 errors, on current main.
- `cargo test -p net --no-default-features` → 1909 passed, 0 failed.
- `cargo test -p fs` → all suites 0 failed.
- `sock_opts` module in `crates/kernel/net/src/lib.rs` is no longer
  `#[cfg]`-gated at all (line 134, confirmed ungated).

Several STALE rows found in adjacent ranges (25/26/27/31/32/36/46/51 in
15-135, 251/292 in 231-309) are all instances of the same now-fixed
`sock_opts` gating defect. Rows in 136-230 asserting the same `net`/`fs`
build-failure claim should be checked first — that is the highest-yield
place to look for more STALE rows in the unaudited range.
