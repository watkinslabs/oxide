# Session hand-off

## Headline
Branch **F369-dentry-mount-tree** (off main, 4 commits, UNMERGED — boot does
not reach login yet, so the smoke gate blocks merge). Delivered the user's
explicit demand (dentry-keyed mount crossing, no strings) + the full systemd
machine_id_setup path + real netlink. Remaining blocker is **timer/clock/
scheduler accuracy**, isolated below.

## Commits this session (F369-dentry-mount-tree)
- `5449322f` feat(netlink): real mutable iface flags (IfaceEntry.flags) +
  unified socket recv. RTM_SETLINK mutates flags, GETLINK reports them.
- `01d1d8cd` refactor(vfs): **mount crossing keyed by dentry identity, not
  path string**. Dentry.mounted_root + set_mounted_root; path_lookup crosses
  by Arc identity (deleted the absolute_path()-stringify + prefix match);
  vfs::mount::register* wire the mountpoint dentry via a DENTRY_RESOLVER hook
  (kernel installs pathresolve::resolve_dentry); crossing root =
  fs.root().or_else(|| fs.lookup(mp)) so mounts SHADOW the underlying dir.
  mount_root_at kept as a table QUERY only. 69 vfs hosted tests pass.
- `efa06dc2` fix(syscall): **real openat dirfd resolution** (pathresolve::
  resolve_at — was IGNORED kernel-wide; every *at with a real dirfd resolved
  against cwd) + **MS_REMOUNT before MS_BIND** (remount carries NULL source;
  bind branch EFAULTed on it).
- `c8ffe1b4` fix(netlink): **honour MSG_PEEK in recvmsg** (sd-netlink sizes its
  buffer with recvmsg(MSG_PEEK|MSG_TRUNC) first; we dequeued on peek → ack
  eaten). NetlinkSocket::peek_front; sys_recvmsg passes flags.

## machine_id_setup: FULLY WORKING (verified by trace, under TCG)
systemd: open /etc/machine-id (dirfd-relative openat now resolves correctly),
write id to /run/machine-id, bind it onto /etc/machine-id via /proc/self/fd/4
(dentry crossing follows the magic symlink to the real target), remount RO.
No errors. The openat-dirfd + MS_REMOUNT + dentry-bind fixes closed this.

## REMAINING BLOCKER: timer/clock/scheduler accuracy (NOT netlink, NOT vfs)
loopback_setup (vendor/systemd/.../src/shared/loopback-setup.c) sends 3 async
reqs: RTM_NEWADDR v4 (USEC_INFINITY), v6 (USEC_INFINITY), RTM_SETLINK
(LOOPBACK_SETUP_TIMEOUT_USEC = **5s**). Trace proved all 3 acks delivered
correctly (seq match, type=NLMSG_ERROR, err=0/-97/0) AND consumed by sd_netlink
(peek+consume each). The netlink path is CORRECT.

But sd_netlink's `process_running` calls `process_timeout()` BEFORE
`dispatch_rqueue()` — so once 5s of *guest* CLOCK_MONOTONIC elapses it fires
state_up with -ETIMEDOUT and returns before dispatching the already-received
SETLINK ack (orphaned). → "Failed to bring loopback interface up: Operation
timed out", then boot wedges.

Root cause = guest clock skew. monotonic_ns = rdtsc()*1e6/TSC_KHZ
(crates/arch/hal-x86_64/src/lib.rs:312). Under **TCG** (what all my boots used —
KVM is gated behind OXIDE_QEMU_KVM, ~10-12min boots) the emulated TSC advances
in bursts, so the 5s deadline misfires.

Booted with **OXIDE_QEMU_KVM=1** (KVM confirmed, /dev/kvm rw, "Detected
virtualization kvm"): boot wedges EARLIER, at "Initializing machine ID from
random generator" (before the bind). getrandom uses RDRAND (non-blocking,
hwrng.rs) so it's NOT entropy — it's the cooperative scheduler/timer-wake
behaving differently under KVM (kernel was tuned under TCG; see memory
project_scheduling_state: cooperative-with-timer-wake, iretq-frame gap). NB:
CLAUDE.md says the dev box normally uses KVM (<1min boots) — so KVM is the
intended env and this KVM machine-id wedge may be pre-existing OR exposed by
this branch; UNVERIFIED whether main-without-branch reaches login under KVM.

## First task next session
1. Determine if `main` (no branch) reaches login under `OXIDE_QEMU_KVM=1 make
   SMP=2 qemu-x86` — establishes whether the KVM machine-id wedge is
   pre-existing or introduced by F369. (Kill stale qemu + free :2222 first.)
2. If pre-existing: the timer/scheduler subsystem needs work (clock accuracy +
   cooperative-scheduler wake under KVM) before any of this boots to login —
   that's the real gate, separate from VFS/netlink.
3. F369's 4 commits are correct + spec-lint clean + both arches build; they
   merge once login is reachable (smoke gate). Do NOT merge until then.

## Harness notes
- KVM: `OXIDE_QEMU_KVM=1 make SMP=2 qemu-x86` (fast). TCG default is ~10-12min.
- Run boots ALONE in background; never pkill/sleep/`&` in the same compound;
  free :2222 (ss -ltnp|grep 2222 → kill -9) before each boot.
- spec-lint clean; netlink crate has NO klog dep (trace in kernel/src instead).
