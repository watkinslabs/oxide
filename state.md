# Handoff — sysinit stall = systematic per-operation ext4 journal commits

Main = `0da855f8`. Goal: console login → live-gnome. Blocker: sysinit crawls
(hwdb times out at 90s; every fs-heavy service ~20-90× too slow).

## Landed this session
- **B679 / PR#2880 (merged):** ext4 writeback batching. `writeback_idxs` flushed
  each dirty page as its own journal commit (N-page flush = N commits × 3
  `dev.flush()` each). Now one `run_journaled` around the page loop → 1 commit.
  Measured 800→332 write-ops for 40 pages (58% fewer), commits 40→1. Hosted:
  `ext4/tests/writeback_amp_image` + `writeback_ryw_image` (read-your-writes
  guards the O(n²) re-extend a naïve batch causes). Boot-neutral (A/B: main +
  fix stall identically at the hwdb 90s timeout).
- **F698 (prior, merged):** XSAVE/AVX ctxsw fix (heap `Box<FpuArea>`). Real
  Linux-compat gap; does NOT fix hwdb.

## Diagnosis — the REAL blocker (refined 2026-07-09, boot A/B on KVM)
hwdb does NOT hang forever: systemd times it out at **99.6s** (`start operation
timed out. Terminating.` → SIGTERM) and sysinit continues — but the boot is
still in early sysinit at **238s**. The slowness is **SYSTEMATIC, not
hwdb-specific**: every fs-heavy service (hwdb trie, tmpfiles file-creation, …)
is 20-90× too slow because **ext4 commits+flushes the journal PER OPERATION**.
`run_journaled` commits at each top-level scope (each `create_file`, `write_at`,
`unlink`, `writeback`); `commit_metadata` does **3 `dev.flush()` barriers** per
commit (virtio flush = host fsync). Linux jbd2 batches thousands of ops into ONE
running transaction committed every ~5s / on fsync.

**Conclusively ruled out** (evidence in memory `hwdb-blocker-ext4-writeback-commits`):
cacheability (PAT/MTRR = WB, user PTEs no PCD/PWT), TLB over-flush (CR3 only on
AS-change), AVX/XSAVE (F698 doesn't fix), page faults (zero), unbounded output.

## NEXT (the real GOAL-1 unblocker — big, do it disciplined)
**jbd2-style cross-operation transaction batching.** A persistent running shadow
transaction that individual metadata ops JOIN (read-your-writes already works
within an open shadow — proven by tests), committed by a trigger (fsync/sync
syscall / shadow-size threshold / periodic timer / unmount) instead of per
top-level `run_journaled` scope. Removes the per-op commit+3-flush tax.
- Design carefully: some callers rely on run_journaled durability-on-return
  (fsync/sync MUST force a commit). Distinguish "join running txn" (create,
  write, unlink, writeback) from "force commit" (fsync/fdatasync/sync/unmount).
- **Build hosted tests FIRST** (extend `ext4/tests/writeback_amp_image` pattern
  with StatsDev): assert N file-creations commit ≈ once, not N times. Do NOT
  boot-iterate the journal core.
- Watch: shadow memory growth (need a size-based commit trigger); crash
  semantics (losing <5s of un-fsync'd metadata on crash is Linux-correct).

## Possibly separate: hwdb-specific CPU
Even with writeback batched, hwdb's own `trie_store_nodes`→glibc fwrite/malloc
loop may be CPU-heavy (buffered writes are cheap). Re-profile AFTER cross-op
batching lands — the commit tax may have been masking/dominating it.

## First command next session
`cd /home/nd/oxide/kernel && git log --oneline -3`  # confirm main
Then: design cross-op journal batching; write the hosted StatsDev commit-count
test before touching `crates/kernel/ext4/src/mount/core.rs run_journaled`.
