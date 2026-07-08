# Desktop boot blockers — status 2026-07-08

Goal: boot the glibc GNOME image to a visible gdm greeter. Chain of blockers,
each fixed reveals the next. Boots done on a CLEAN host (codex agent paused).

## Status legend
FIXED = merged. VERIFIED = boot-confirmed, branch not merged. OPEN = not fixed.

| # | Blocker | Status | Branch / PR |
|---|---------|--------|-------------|
| 1 | qemu hardcoded `vhost-vsock guest-cid=3` (host-global) → parallel Codex agent's boot-loop wedged EVERY boot at launch | **FIXED** | PR #2848 merged (`buildns::qemu_vsock_cid`, per-launch CID+ports) |
| 2 | systemd-journal-flush timeout | **not a bug** | pure codex CONTENTION; passes on a clean host |
| 3 | SIGCHLD zombie-reap wedge: init parks in epoll_wait, exit_group children pile up unreaped (~13), boot freezes ~10s | **VERIFIED FIXED** | `B661-signalfd-sigchld-reap` (signalfd poll/read consult `has_zombies`). Proof: init reaps went 0→15, boot advances past the wedge |
| 4 | **Demand-paging / ELF library loading is ~200× too slow** | **OPEN** ← desktop wall | ext4 read / fault path |

## Blocker #4 detail (the current wall)
Clean-host boot (SMP=1, no contention): **552s to reach `local-fs.target`**
(normally ~2-3s). Time is NOT uniform — it's a few HUGE discrete stalls:
- **271s stall** right after `[10.4s] elf-load: interp place ok` → the next
  output is `systemd-tmpfiles-setup-dev` doing its first `mknod` at [281s].
- **241s stall** after a later `wait4 reap` (another service's exec).
- 30s / 24s / 13s stalls, all after `elf-load: interp place ok` or a reap.

Interpretation: each dynamically-linked service, after the kernel places
`/lib64/ld-linux-x86-64.so.2`, spends MINUTES before it runs — the dynamic
linker demand-paging the binary's shared libraries (libc, libsystemd, …). Every
`.so` page fault → an ext4 read. So loading one binary = hundreds/thousands of
individual slow page-fault reads.

Prime suspects (investigate hosted, NOT boot-per-hypothesis):
- **No readahead on file-backed mmap page faults** — Linux faults in clusters +
  does async readahead; if oxide faults ONE 4K page per fault with a full extent
  walk + block read each time, a 2 MB `.so` = 512 slow round-trips. Add mmap /
  page-cache readahead. (Highest-ROI lead.)
- ext4 read path per-block cost: `resolve_pblock` extent walk per block (O(depth)
  I/O each), framecache `fill_page` one block at a time. Batch/cache.
- A writeback/read livelock in the framecache (see [[journald-empty-ext4-writeback]]).

NEXT: hosted harness — mmap a multi-MB file from an ext4 image, fault every page,
count block reads + measure; confirm it's O(pages) slow round-trips with no
readahead. Then add readahead / batched extent reads. THEN one boot to confirm
graphical.target.

## Ready but unmerged
- ext4 stack `B656`–`B660` (A1 mtime, A2 s_state, A4 extent-bound, A3 rmdir, B3
  msync) — hosted-tested, both arches build. See `scratch/ext4fix.md`.
- `B661` SIGCHLD reap — verified, builds. Push after a clean boot confirms.

## Boot hygiene (learned painfully this session)
- `pkill -9 qemu` WORKS here. But ONE boot at a time — overlapping make/boot runs
  collide on `target/builds/default/*.img` ("Is another process using the image").
- Don't `pkill cargo` mid-build (corrupts the build → make exit 2).
- The qemu MCP path stalls at SeaBIOS even clean — use `make qemu-x86` /
  boot-smoke. Capture serial to your OWN log path; boot-smoke rm's its /tmp log.
