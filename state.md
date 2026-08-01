# state.md — session hand-off

Main `351684a44`, clean: 0 open PRs. Syscall matrix **IMPL 273 / PARTIAL 89 /
LINUX-ENOSYS 22** of 385. Two lanes in flight, both blocked on their own gates —
neither is mergeable as-is.

## Headline: a ring-3 LPE, and GNOME is usable again

`B1638` (#4299) found that the kernel set `CR4.FSGSBASE=1` on every CPU while
running a **no-`swapgs`** model, so `GS_BASE` pointed at the kernel per-CPU area
*in ring 3*. Unprivileged `wrgsbase <attacker ptr>` made the next `syscall`
execute `mov gs:[16], rsp` / `mov rsp, gs:[8]` against that base — arbitrary
kernel write plus stack pivot, i.e. LPE from any process. Fixed by moving the
per-CPU base to `wrmsr(IA32_GS_BASE)` and clearing `CR4.FSGSBASE`; a real
`ARCH_SET_GS` then forced the x86_64 entry model onto `swapgs` across all eight
ring transitions incl. paranoid entry/exit for the four IST vectors.

Two Yama holes went with it: `pidfd_getfd` and `process_vm_readv/writev` used the
READ-class ladder, so at `ptrace_scope=1` a same-uid process could read another's
memory. And seccomp ran **before** the ptrace entry stop, letting a tracer
substitute a call the filter had already approved.

## Merged this session

| PR | What it fixed |
|---|---|
| #4299 | ptrace/prctl/arch_prctl/personality; the LPE above; 3 prctl values stored-and-never-read |
| #4301 | fanotify delivery: perm events drained ahead of their notifications, EACCES where Linux says EPERM, an accessor spinning on `tick_yield()` with no signal check |
| #4304 | fanotify completion: `FAN_REPORT_MNT` fired for real, hashed merge index, `FAN_MARK_EVICTABLE` fixed at the root, `RootfsState::fsid()` three-way identity split |
| #4305 | GNOME pointer: the guest was never offered an **absolute** pointer (`absolute: False` on every device) |
| #4306 | GNOME display: connector published **one** mode; `SET_SCANOUT` ran *before* `TRANSFER`, binding the display to an unwritten buffer every frame |

## Open: two lanes, both self-blocked

**B1641 (socket cluster).** `net` 1511/0, `syscalls` 998/0, but **`make
stack-gate` FAILs on aarch64**: `oxide_svc_save_block` 13424 B against a 13000 B
ceiling (x86 passes). Bisected to this lane's own merges. Two fixes moved it the
*wrong* way — `#[inline(never)]` → 13552 (frames sum instead of overlap), boxing
the option blocks → 13440, which disproves the whole "shrink the socket" family.
Real cause: `tcp_connect_reserved_min_hop` builds a 512 B `TcpConn` on the frame
then moves it into a function returning 608 B **by value** into `Arc::new` —
1120 B of a 1872 B inlined frame. Fix = allocate first, initialise in place.
Also needs a boot before merge: `IP_MULTICAST_ALL` behaves as `MC_ALL=0` where
Linux defaults to 1, changing mDNS/LLMNR delivery.

**B1648 (GNOME left-click).** Left-click doesn't launch; the `New Window`/`Unpin`
menu appears instead. **Coordinates are proven correct** (injected pixel
hover-lights the icon and anchors its tooltip there), and the user confirmed by
hand that a genuine long press opens that same menu — so *every ordinary click is
read as a long press*. Kernel is clean to the evdev node on both arches: BTN_LEFT
press+release, each its own `SYN_REPORT`, ~0.5 ms apart. Prime suspect:
`evdev_queue.rs` stamps `tv_sec`/`tv_usec` at **drain** time, not when the device
reported the event, so a delayed drain inflates the apparent press duration.
Decisive measurement = `libinput debug-events` in-guest during an injected click.

## Named follow-ups, unowned

- **Citation debt is tree-wide**: 273 files with `.c:NNN`, 113 with
  `include/uapi`, 50 with `.h:NNN`, 10 naming the local reference tree. Repo rule
  forbids citing external implementation sources in tree text.
- **42 `find(...).unwrap()` source-grep assertions** break on unrelated refactors
  and already manufactured one false flake.
- **Phantom tests live in the tree**: `net/src/sock_v6.rs` and
  `sock/{udp,ops,send}.rs` are target-gated, so their test modules have never
  executed once. Same trap in the other direction: `procfs/ctl.rs` is gated, so
  `cargo check` compiles none of it and breakage appears only in the kernel build.
- Queued net work: request-sock minisock (`TCP_DEFER_ACCEPT` establishes
  server-side where Linux leaves the peer retransmitting), `TCP_ZEROCOPY_RECEIVE`,
  fast-open, `IP_OPTIONS` on transmit.
- GPU: damage rectangles not plumbed from DRM (whole framebuffer every present);
  EDID negotiated but `GET_EDID` never issued; no vblank pacing; PRIME is EINVAL.
- `absinfo.rs::eviocgabs_decodes_the_axis_from_the_request_number` was pinned
  from memory, not verified — may encode a divergence. B1648 owns re-verifying it.

## Traps that cost real time this session

- **Matrix column indexing.** `scratch/syscall-compliance-matrix.md` is
  pipe-delimited with status at awk `$9` / python `f[8]`, branch at `$10`, notes
  at `$13`. Python's split index is one *less* than awk's field number; getting
  that wrong overwrote the branch column on four rows (repaired in #4302).
- **Merged branches reappear on the remote.** `--delete-branch` works, but a
  sub-lane agent pushing *after* the parent PR merges recreates the ref. 13 stale
  remote branches accumulated unnoticed because cleanup only checked local ones.
  Re-check `git branch -r` after each merge.
- **Do not remove a worktree whose lane is still running.** Doing so mid-boot
  orphaned a QEMU against a deleted build directory and killed the run.
- **Verify against primary source even when the instruction comes from the
  integration owner.** A directive to relax the GRO flow key was wrong — it was
  derived from the device-level pass alone, while a second transport-level
  comparison owns exactly the fields it said to drop (the two IPv6 masks are
  exact complements). The sub-lane refused and was right.
