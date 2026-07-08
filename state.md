# Handoff — boot env FIXED (qemu CID conflict); chasing graphical.target

## THE "BOOT BROKE ALL NIGHT" ROOT CAUSE — FIXED + MERGED (PR #2848)
NOT a host fault, NOT the kernel (an earlier handoff wrongly blamed SeaBIOS).
A parallel **Codex `--yolo` agent** in worktree
`/home/nd/oxide-wt/B656-vt-kd-ioctl-compliance` looped `make smoke`; its qemu held
the HOST-GLOBAL `vhost-vsock guest-cid=3`. Both the MCP and xtask launchers
HARDCODED cid=3 (+ gdb 1234, ssh 2222), so every OTHER boot on the box died at
launch: `vhost-vsock: unable to set guest cid: Address already in use` (aborts
before SeaBIOS — the GDB stub then showed a stale reset vector, misread as a
"SeaBIOS hang"). Worktrees isolate files, NOT the CID/port namespace.
- **FIX (merged to main):** per-launch vsock CID + gdb/ssh ports from repo path +
  build id + pid (`buildns::qemu_vsock_cid`/`qemu_host_port`); overrides
  OXIDE_QEMU_{VSOCK_CID,GDB_PORT,SSH_PORT}. Both arches. Multiple workers coexist now.
- `pkill -9 qemu-system` DOES work here (old lesson §7 is stale) — but kill the
  RESPAWN loop first (`pgrep -af 'make smoke|boot-smoke'`) or qemu respawns in secs.

## BOOTING — what works
- `./tools/boot-smoke.sh x86 <timeout>` (make/xtask path) BOOTS to systemd
  userspace. Use a UNIQUE `SMOKE_KEEP_LOG=<path>` — codex writes the SAME
  /tmp/oxide-boot-smoke-x86-*.log, so `ls -t` grabs the wrong log (check for
  `Leaving directory 'oxide-wt'` to spot codex's).
- qemu MCP path STALLS at SeaBIOS 0x82e7 even with cid free — separate MCP bug,
  not chased. Use boot-smoke.
- Two agents both booting ≈ halves KVM throughput → systemd service timeouts.
  For a clean desktop boot, PAUSE the codex agent.
- Don't do git checkouts while a boot-smoke build runs (corrupts the build).
  Don't run overlapping boots. My bash tool's 120s timeout kills a fg boot — always
  run boot-smoke with run_in_background and WAIT for the completion notification.

## DESKTOP BLOCKER (current frontier)
Boots reach systemd but stop at **`systemd-journal-flush.service: Failed with
result 'timeout'`** (Flush Journal to Persistent Storage) — same journald↔ext4
writeback issue as prior sessions. May be contention OR a real bug. IN FLIGHT:
boot-smoke of `int-desktop-verify` (ext4 stack + qemu fix) with
SMOKE_MARKER='Reached target graphical.target' (log scratchpad/final.log) to see
if the A1/A2 ext4 fixes get past it to gdm.

## READY (local branches; hosted-tested + both arches build; NOT pushed)
Stacked off main: **A1 B656 → A2 B657 → A4 B658 → A3 B659 → B3 B660**. Integration
branch `int-desktop-verify` = that stack + the merged qemu fix. See scratch/ext4fix.md.
- A1 mtime-on-write (frozen-1970), A2 s_state lifecycle, A4 extent-descent bound,
  A3 rmdir reclaim, B3 msync EIO. ext4 87 lib + ~90 integ + vfs 98 tests green.
- To land: rebase the stack onto main (has qemu fix now), boot-verify, push+PR A1→B3.

## NEXT
1. Read scratchpad/final.log: journal-flush pass? graphical.target reached?
2. journal-flush still fails → real ext4 writeback bug (unwritten-extent / journal
   file); use a hosted harness, not boot-per-hypothesis.
3. Then push the ext4 stack + resume gdm greeter (prior blocker: gdm session
   wrapper SIGTERM after ~45s hang — see [[greeter-blocker-logind-seat]]).

## FIRST COMMAND NEXT SESSION
`pgrep -af 'make smoke|boot-smoke' | grep oxide-wt   # codex still competing?`
