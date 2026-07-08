# Handoff — ext4 Linux-compliance batch (ext4fix.md Phase A) — BOOT ENV DOWN

## BLOCKER (needs host action — read first)
QEMU cannot boot on this box this session. **SeaBIOS wedges in an infinite loop
at RIP=0xec1a** (real-mode, CS=f000, zero guest serial) on EVERY boot, *before
the kernel runs*. Confirmed conclusively — ruled OUT:
  - stale qemu (reaped via MCP, `ps` count = 0),
  - disk/RAM exhaustion (/home 2 TB free, 50 GB RAM free),
  - KVM-specific fault (a pure **TCG** boot hangs identically at 0xec1a),
  - slowness (regs BYTE-IDENTICAL across a 5-min gap at ~4.5 & ~9.5 min TCG —
    frozen state rax=0x11 rsp=0x7ff60, a tight loop, not disk-probing).
So it's a host/QEMU/SeaBIOS fault, not the kernel and not KVM. The bash sandbox
cannot `pkill` qemu (lesson §7). **Fix: user reboots the dev box (or reloads the
kvm module / checks the qemu-system + SeaBIOS install), then re-run boot-verify
below.** Until then the pre-push smoke hook will hang → branches are LOCAL-ONLY,
unpushed. (~6 boots + a patient 10-min TCG spent confirming this; do NOT keep
retrying boots — it's environmental, per lesson §7/§8.)

## READY TO PUSH (stacked, hosted-verified + both-arch RELEASE-built, NOT pushed)
Branch chain off `main`: **A1 → A2 → A4 → A3 → B3**
- `B656-ext4-mtime-on-write` (A1, §7.1): write/fallocate/create stamp mtime/
  ctime/crtime; vfs CLOCK_REALTIME provider + file_update_time. Fixes frozen-1970.
- `B657-ext4-sstate-lifecycle` (A2, §2.2): mark s_state dirty on mount / clean
  on unmount, ++s_mnt_count, stamp s_mtime.
- `B658-ext4-extent-descent-bound` (A4, §3.1): bound extent-tree descent +
  recursion (EXT4_MAX_EXTENT_DEPTH + strictly-decreasing depth); reject corrupt/
  cyclic trees → CorruptExtentTree instead of infinite I/O loop / stack overflow.
- `B659-ext4-rmdir-reclaim` (A3, §4.1/§4.2): rmdir frees victim blocks+inode,
  drops used-dirs, decrements parent nlink (Mount::rmdir).
- `B660-ext4-msync-eio` (B3, §7.4): msync propagates writeback EIO instead of
  swallowing it (flush_all_dirty → Result; sys_msync returns -EIO like fsync).
Each has its own hosted test (ext4 tests/*.rs) + green ext4 (87 lib + ~90
integration) & vfs (98) suites. Both x86_64 + aarch64 kernels build clean.

## BOOT-VERIFY + PUSH SEQUENCE (once box reboots)
1. `pkill -9 qemu-system` (host), confirm none left.
2. Boot-smoke B659 (has the whole stack): qemu MCP x86_64, wait `oxide login:`.
   Also confirm A1: after boot, `stat` any freshly-written file shows a
   2024+ mtime (not 1970); `journalctl` writes (with an empty /var/log/journal
   in the image — see [[journald-empty-ext4-writeback]]).
3. If green: push each branch bottom-up, open+merge PRs in order A1→A2→A4→A3
   (they stack). Delete branches + worktrees on merge.
4. Flip scratch/ext4fix.md rows VERIFIED-LOCAL → MERGED.

## NEXT (ext4fix §9, after the batch lands)
- A5 jbd2 durability (mark journal dirty before txn) — §6.1. A6 REVOKE — §6.2.
  (Crash-safety; want boot-verify, so do after env is back.)
- CAUTION: B1 (csum-verify-on-read + feature-gate at mount, §2.1/2.3), A5/A6
  (jbd2 crash-safety) all touch the mount/boot path — a too-strict change there
  can brick boot, and they CANNOT be safely landed while boot-verify is down.
  Do them once the env is back.
- Boot-independent, hosted-only-safe next item: B2 FS_IOC_GETFLAGS/SETFLAGS +
  i_flags decode (§7.3 — chattr/lsattr; journald uses chattr +C).

## RULES REAFFIRMED
Plans live in scratch/ (new CLAUDE.md rule). Branch counters in metadata/index.md
(B next = 661). No cargo fmt. Author Chris Watkins. No Co-Authored-By.

## FIRST COMMAND NEXT SESSION
`pkill -9 qemu-system 2>/dev/null; git -C /home/nd/oxide/kernel log --oneline main..B660-ext4-msync-eio`
