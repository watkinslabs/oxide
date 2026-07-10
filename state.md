# Handoff — Goals 1+2 complete; Goal 3 blocker is stock-systemd userspace

Main has B703 #2927 + B704 #2929 merged. Goal 1 (console) + Goal 2 (ext4) DONE.
Goal 3 (live-gnome) blocker = CONFIRMED stock-systemd userspace varlink streaming
(NOT a kernel defect; systemd = Fedora RPM binaries, needs sudo image re-compose).

## Goal 1 (console 100% Linux-compat) — COMPLETE this session
console.md re-audited: G1 closed by observation (fbcon scans out — window shows
live kernel log), G3(x86)/G4/G5/G6 all already implemented, full VT/KD ioctl
handshake (VT_ACTIVATE/WAITACTIVE/SETMODE/RELDISP, KDSETMODE, VT_RESIZE→SIGWINCH)
audited real (not stubs). The ONE real remaining divergence — pl011/aarch64 TCSETS
baud reprogram was a no-op — FIXED in **B704** (`pl011_set_termios`: disable→drain
BUSY→program IBRD/FBRD→relatch LCRH→restore CR; UARTCLK=24MHz until DTB-clock;
pure host-tested `pl011_divisor`). console.md §5/§6/bottom-line refreshed to accurate
state. Console is kernel-ready for a getty login; only G2 (userspace) gates it.

## Landed this session
- **B703** vfs: AF_UNIX `bind(2)` materialises the path node via `mknod_child`
  straight off the parent inode op, bypassing namei's `d_instantiate`. A NEGATIVE
  dentry cached by an earlier `stat(path)==ENOENT` then shadowed the new node
  forever (namei walk treats a cached negative as definitive ENOENT → stat ENOENT
  while readdir shows the child). Fix: `mount::drop_stale_negative(abs)` (new child
  module `mount/invalidate.rs`), called from bind after a successful `mknod_child`.
  Hosted regression `dcache::tests::drop_negative_forces_relookup`. Both arches
  build clean. This is a REAL Linux-incompat bug but **NOT the live-gnome blocker**
  (userdb sockets are bound before nss-systemd first stats them → no negative
  cached for them). See [[mknod-bypasses-dcache-negative]].
- Prior (already merged to main): B699/B700/B701/B702 (op_lock livelock, accept
  race, RMW skip, data-write coalescing → hwdb fsync 50s→~30s). ext4 = 100%.

## ★ live-gnome blocker (goal 3) — DEFINITIVE, userspace, not kernel
`systemd-tmpfiles-setup-dev-early` stalls ~249s → never reaches gdm. Root cause
(traced UWSYS/UXDROP, definitive): systemd-userwork workers each ppoll-BLOCK ~15s
per Multiplexer varlink query waiting for the client to send-more-or-close; the
client (nss-systemd, triggered by nsswitch `group: files [SUCCESS=merge] systemd`)
holds the streaming GetMemberships connection OPEN after NoRecordFound (`"more":
true` stream never concludes). 3 workers × ~1 query/15s ⇒ 249s. Across a full 27s
window ZERO InetSocket::Drop / close_writer fired for any userdb socket → the conn
genuinely never closes. **KERNEL af_unix/epoll/timer/IO/close all measured-correct
this session and prior — do NOT re-chase them.** Fix lives in ../images (systemd/
nss-systemd varlink streaming-termination or nsswitch config). See
[[desktop-blocker-tmpfiles-userdbd]].

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`
2. `gh pr create` for B703 if not merged (push was network-flaky this session).
3. Goal 3 is a ../images userspace fix, NOT a kernel change. Either work it there
   (nsswitch `[SUCCESS=merge]` → the streaming query; or nss-systemd stream
   termination) or pick the next kernel audit item from scratch/kernel-audit2.md.

## Gotchas
- NEVER `git add -A` (untracked dumps). Stage explicit paths.
- ext4 work: iterate hosted + e2fsck, don't boot [[ext4-work-no-booting]].
- Boot only via qemu MCP; no repeated long boots [[no-repeated-long-boots]].
- aarch64 `xtask kernel` aborts on missing rootfs img (../images) BEFORE compile;
  to compile-check aarch64 directly: `cargo build -Z build-std=core,compiler_builtins,alloc
  -Z build-std-features=compiler-builtins-mem -Z unstable-options -Z json-target-spec
  --target ./targets/aarch64-unknown-oxide-kernel.json --profile release -p kmain
  -p boot-aarch64 -p kernel-bin-aarch64`.
