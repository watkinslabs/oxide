# state — session hand-off

Branch: **main**. Counters in `metadata/index.md` (AUTHORITATIVE — read+bump per
branch). Dev loop: `tools/boot-smoke-probe.sh x86 <probe>` under `OXIDE_QEMU_KVM=1`
(~20s); `SMP=4 ...` to exercise APs. **GOTCHA:** never `pkill -f qemu-system`
(kills the shell) — use `pkill -9 -x qemu-system-x86_64`. Stale qemu holds the
root.img write-lock; kill all qemu first.

## Merged this run (18 PRs) — linux2.md "is this the Linux way" + a crash fix

- **B120 #1809** real TIOCM* modem + TIOCSPTLCK/GPTLCK pts lock (Inode::on_open).
- **F439 #1810** rtnetlink multicast (bind nl_groups + ADD/DROP_MEMBERSHIP +
  rtnl_multicast; netlink/src/mcast.rs).
- **C87 #1811** dropped dead init() shims + the unused iouring crate.
- **F440 #1812 / F441 #1813** netfilter base-chain hooks wired into the IPv4 AND
  IPv6 packet paths; family-aware eval (net/src/netfilter_hook.rs).
- **F442 #1814 / F443 #1818** tracefs trace_marker ring buffer + consuming/blocking
  trace_pipe (tracefs/src/ring.rs).
- **B121 #1815 / B122 #1817** ext4 depth-agnostic block resolution (read + RMW
  write) + truncate at depth>=1.
- **C88 #1816** user doc cleanup + Cargo.lock sync.
- **F444 #1819 / F445 #1820 / F446 #1821** fanotify §2.13 DONE: real
  fanotify_event_metadata + object fd; FAN_OPEN_PERM (blocks open until verdict);
  FAN_ACCESS_PERM (read hook). fs/src/inotify.rs.
- **B123 #1822** TERM=linux→xterm-256color so htop/vim use the alt screen (console
  IS an xterm emulator: keyboard F1=ESC O P, emulator handles ?1049/DEC/256color).
- **B124 #1823** CRITICAL SMP crash fix: device-MMIO BARs were spliced into the
  active boot-AS PML4 but NOT the kernel master PML4 that APs CR3 to (smp_x86:348),
  so an AP GPU-flush softirq #PF'd NP on a virtio BAR (0xffff_fd00…) → CPU-STALL
  cascade. resync_kernel_master() copies kernel-half PML4[256..512] into the master
  after PCI enum. Verified SMP=4 boots clean. (arm immune: split TTBR0/TTBR1 → one
  shared kernel tree.)
- **F447 #1825 / F448 #1826** (§2.12) tracefs real tracepoints: per-CPU LOCKLESS
  ring buffer (percpu_ring.rs — wait-free SPSC, drop-on-full, 5 unit tests);
  trace_marker/trace/trace_pipe rewired onto it; **sched_switch static
  tracepoint** (sched install_sched_switch_hook fired at the switch site; tracefs
  records wait-free; events/sched/sched_switch/enable gates it = install/clear
  the hook; available_events lists it). Probe tracesched_probe.
- **B125 #1824** stall detector: now.saturating_sub (was wrapping) — kills the
  bogus "18446744073s" false stall from cross-CPU clock skew.

## linux2.md remaining — all LARGE / dedicated efforts now

The bounded/testable gaps are done. What's left:
- **§2.11 eBPF** verifier + JIT/interpreter (security/src/bpf.rs) — large, high value
  (seccomp/tracing/tc/XDP).
- **§2.12 tracefs**: foundation + sched_switch DONE (F447/F448). REMAINING (same
  proven pattern): more tracepoints (sys_enter/sys_exit — hook at the syscall
  entry/exit site), per-event format files (events/.../format), function tracer
  (current_tracer=function — much larger).
- **§3 X11/Wayland** (distro endgame) — huge.
- §2.8 ext4 append tree-growth past depth 2 — pathological (needs ~millions of
  non-contig extents), clean-failing, not brute-force testable. Low priority.

## First command next session

    sed -n '1,40p' crates/kernel/security/src/bpf.rs   # if taking eBPF
    # or build the per-CPU lockless trace ring buffer for §2.12 tracepoints
