# state — session hand-off

Branch: **main**. Branch counters live in `metadata/index.md` (AUTHORITATIVE —
read+bump per branch). Dev loop: `tools/boot-smoke-probe.sh x86 <probe>` under
`OXIDE_QEMU_KVM=1` (~20s). **GOTCHA: never `pkill -f qemu-system`** — matches
the bash-tool's own cmdline → SIGTERMs the shell (exit 144). Use
`pkill -9 -x qemu-system-x86_64`. Stale qemu holds `kernel/blobs/root-x86_64.img`
write-lock → next boot fails "Failed to get write lock"; kill all qemu first.

## Merged this run (linux2.md loop — "is this the Linux way", no fakes)

All x86+arm boot-verified, spec-lint clean:
- **B120 #1809** real TIOCM* modem (serial software-MCR; VT+pty → ENOTTY) +
  TIOCSPTLCK/GPTLCK pts lock (pair allocates LOCKED; slave-open EIO until
  unlockpt; added `Inode::on_open` hook). Probe tty_ioctl_probe.
- **F439 #1810** real rtnetlink multicast: bind nl_groups + NETLINK_ADD/DROP_
  MEMBERSHIP + `rtnl_multicast()` → RTM_NEW*/DEL* broadcast to subscribed
  NETLINK_ROUTE sockets. New `netlink/src/mcast.rs`. Probe nlmcast_probe.
- **C87 #1811** (§2.9) dropped stale `init()->NotImplemented` shims (net,tty);
  deleted dead `crates/kernel/iouring` crate (0 uses).
- **F440 #1812** (§2.10) wired all netfilter base-chain hooks into the **IPv4**
  packet path: PRE_ROUTING+LOCAL_IN (deliver_rx), LOCAL_OUT+POST_ROUTING (TX,
  via nf_output). FORWARD intentionally unwired (host stack, no forward path).
  Bridge split to `net/src/netfilter_hook.rs`.
- **F441 #1813** family-aware netfilter + wired the **IPv6** path too. eval gains
  `family`; expr engine per-family (transport offset, meta nfproto/l4proto).
- **F442 (this branch)** real tracefs `trace_marker`: write → timestamped record
  in a global ftrace ring buffer; `trace` read renders Linux ftrace format +
  write clears; `tracing_on` gates. `tracefs/src/ring.rs`. Probe tracemark_probe.

## linux2.md remaining (validated real gaps — each a dedicated session)

- **§2.8 ext4 write extent depth** caps at 2 (Linux=5). `extent_rw.rs` is
  per-depth-specialized (append_inline/depth1/depth2 → DepthUnsupported). Real
  fix = a RECURSIVE extent-tree insert (node splits propagate up), NOT another
  append_depthN. Correctness-critical (fs corruption risk) → build a hosted
  harness that forces deep trees (big sparse files) FIRST, then rewrite.
- **§2.11 eBPF** verifier/JIT (`security/src/bpf.rs`) — very large.
- **§2.12 tracefs** beyond trace_marker: per-CPU ring buffers, real tracepoints
  (sched_switch/sys_enter anchors), trace_pipe blocking read, per-event enable.
- **§2.13 fanotify** real semantics (own event format + perm events) — currently
  shimmed onto inotify (`fs/src/inotify.rs`).
- **§3 X11/Wayland** — huge.

## First command next session

    sed -n '40,60p' crates/kernel/ext4/src/extent_rw.rs   # the depth ladder to replace
