# Handoff — ext4 Linux-compliance batch (ext4fix.md Phase A) — BOOT ENV DOWN

## BLOCKER (needs host action — read first)
QEMU cannot boot on this box this session. **SeaBIOS hangs at RIP=0xec1a**
(real-mode, CS=f000, zero guest serial) on EVERY boot — verified across **KVM
and TCG**, 5 boots, 4 different build namespaces, all hang *before the kernel
runs*. So it is NOT the kernel and NOT KVM-specific; it's host/QEMU/SeaBIOS
state. One stale `greeter-20260708T120409` qemu was reaped via the MCP early on
(that fixed a contention BIOS-stall), but fresh boots still hang. The bash
sandbox cannot `pkill` qemu (lesson §7). **Fix: user reboots the dev box (or
resets KVM/qemu), then re-run the boot-verify below.** Until then the pre-push
smoke hook will hang, so the branches below are committed LOCAL-ONLY, unpushed.

## READY TO PUSH (stacked, hosted-verified + both-arch RELEASE-built, NOT pushed)
Branch chain off `main`: **A1 → A2 → A4 → A3**
- `B656-ext4-mtime-on-write` (A1, §7.1): write/fallocate/create stamp mtime/
  ctime/crtime; vfs CLOCK_REALTIME provider + file_update_time. Fixes frozen-1970.
- `B657-ext4-sstate-lifecycle` (A2, §2.2): mark s_state dirty on mount / clean
  on unmount, ++s_mnt_count, stamp s_mtime.
- `B658-ext4-extent-descent-bound` (A4, §3.1): bound extent-tree descent +
  recursion (EXT4_MAX_EXTENT_DEPTH + strictly-decreasing depth); reject corrupt/
  cyclic trees → CorruptExtentTree instead of infinite I/O loop / stack overflow.
- `B659-ext4-rmdir-reclaim` (A3, §4.1/§4.2): rmdir frees victim blocks+inode,
  drops used-dirs, decrements parent nlink (Mount::rmdir).
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
- Phase B hosted-friendly items usable even before boot: B3 msync EIO (§7.4),
  B2 FS_IOC_GETFLAGS/SETFLAGS (§7.3), B1 csum-verify-on-read + feature-gate at
  mount (§2.1/2.3 — P0, hosted-testable with a corrupted fixture).

## RULES REAFFIRMED
Plans live in scratch/ (new CLAUDE.md rule). Branch counters in metadata/index.md
(B next = 660). No cargo fmt. Author Chris Watkins. No Co-Authored-By.

## FIRST COMMAND NEXT SESSION
`pkill -9 qemu-system 2>/dev/null; git -C /home/nd/oxide/kernel log --oneline main..B659-ext4-rmdir-reclaim`
