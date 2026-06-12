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
- **F442 #1814** real tracefs `trace_marker`: write → timestamped record in a
  global ftrace ring buffer; `trace` read renders Linux ftrace format + write
  clears; `tracing_on` gates. `tracefs/src/ring.rs`. Probe tracemark_probe.
- **B121 #1815** (§2.8) ext4 depth-agnostic block resolution: one `resolve_pblock`
  descends the extent tree any depth (0..=5); read_file_block + write_file_block
  {,_meta} use it. Fixed real bug: RMW write into depth>=1 files was
  DepthUnsupported. Test rmw_write_and_read_into_depth1_file.
- **C88 #1816** chore: removed user's stale root-level scratch .md + synced
  Cargo.lock (tracefs deps from F442).
- **B122 #1817** (§2.8) ext4 truncate at depth>=1 (was DepthUnsupported — any
  multi-extent file failed). Recursive shrink walk: free_subtree reclaims
  orphaned data+metadata; emptied tree resets to depth-0; i_blocks recomputed.
  Tests truncate_depth1_frees_tail_and_keeps_head + _to_zero_resets_to_empty.
- **F443 #1818** (§2.12) real consuming/blocking trace_pipe over F442's buffer:
  read drains+renders records (vs `trace` snapshot); blocking parks via
  tick-yield, O_NONBLOCK→EAGAIN; `pending` absorbs short reads. Probe
  tracepipe_probe.

## linux2.md remaining (validated real gaps — each a dedicated session)

- **§2.8 ext4 APPEND tree-growth past depth 2** — LAST depth cap in ext4.
  read/RMW-write (B121) + truncate (B122) are now depth-agnostic. Append
  (`extent_rw.rs` append_inline/depth1/depth2) still returns ExtentTreeFull/
  DepthUnsupported past depth 2 — but this is a CLEAN failure (no corruption)
  on a PATHOLOGICAL case (depth>=3 needs ~millions of non-contig extents).
  Low priority + not brute-force testable on the 1 MB mini.img. Proper fix =
  RECURSIVE rightmost-append (splits propagate up) replacing the 3 hardcoded
  handlers; do it WITH a large fragmented mkfs fixture so depth>=3 is forcible.
- **§2.11 eBPF** verifier/JIT (`security/src/bpf.rs`) — very large.
- **§2.12 tracefs** beyond trace_marker: per-CPU ring buffers, real tracepoints
  (sched_switch/sys_enter anchors), trace_pipe blocking read, per-event enable.
- **§2.13 fanotify** real semantics (own event format + perm events) — currently
  shimmed onto inotify (`fs/src/inotify.rs`).
- **§3 X11/Wayland** — huge.

## First command next session

    sed -n '40,60p' crates/kernel/ext4/src/extent_rw.rs   # the depth ladder to replace
