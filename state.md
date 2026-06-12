# state — session hand-off

Branch: **main**. Counters in `metadata/index.md` (AUTHORITATIVE — read+bump per
branch). Dev loop: `tools/boot-smoke-probe.sh x86 <probe>` under `OXIDE_QEMU_KVM=1`
(~20s); `SMP=4 ...` to exercise APs. **GOTCHA:** never `pkill -f qemu-system`
(kills the shell) — use `pkill -9 -x qemu-system-x86_64`. Stale qemu holds the
root.img write-lock; kill all qemu first.

## Merged this run (21 PRs) — linux2.md "is this the Linux way" + a crash fix

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
- **F447 #1825 / F448 #1826 / F449 #1827** (§2.12) tracefs real tracepoints: per-CPU LOCKLESS
  ring buffer (percpu_ring.rs — wait-free SPSC, drop-on-full, 5 unit tests);
  trace_marker/trace/trace_pipe rewired onto it; **sched_switch static
  tracepoint** (sched install_sched_switch_hook fired at the switch site; tracefs
  records wait-free; install-is-enable hook pattern). + sys_enter/sys_exit
  tracepoints (syscall/tracepoint.rs bridge, fired in dispatch). Probes
  tracesched_probe + tracesys_probe.
- **B125 #1824** stall detector: now.saturating_sub (was wrapping) — kills the
  bogus "18446744073s" false stall from cross-CPU clock skew.

## linux2.md remaining — all LARGE / dedicated efforts now

The bounded/testable gaps are done. What's left:
- **§2.11 eBPF** verifier + JIT/interpreter (security/src/bpf.rs) — large, high value
  (seccomp/tracing/tc/XDP).
- **§2.12 tracefs**: per-CPU lockless ring + 3 real tracepoints DONE — sched_switch
  (F448), sys_enter + sys_exit (F449), each enable-gated + in available_events.
  REMAINING (minor/infeasible): per-event format files (low value — `trace`
  already renders text); function tracer needs -pg/mcount instrumentation
  (build-system change). §2.12 substantially complete.
- **§3 X11/Wayland** (distro endgame) — huge.
- §2.8 ext4 append tree-growth past depth 2 — pathological (needs ~millions of
  non-contig extents), clean-failing, not brute-force testable. Low priority.

## First command next session

    sed -n '1,40p' crates/kernel/security/src/bpf.rs   # if taking eBPF
    # or build the per-CPU lockless trace ring buffer for §2.12 tracepoints

## NEXT BIG DIRECTION — gap list (user, this session) toward Linux/desktop/games

User wants breadth on missing subsystems (skip Doom itself for now). Prioritized
by (value × tractability × headless-verifiability):

1. **AUDIO (#1, game-blocker, "effectively absent")** — add a virtio-sound
   (virtio-snd, device_id 0x1059) driver reusing the virtio-pci infra
   (drv-virtio-rng is the simplest template; virtio_drv.rs does the probe/queue
   bring-up). Needs: 4 queues (ctrl/event/tx/rx), PCM control protocol
   (PCM_INFO→SET_PARAMS→PREPARE→START + period buffers), an OSS /dev/dsp (write
   PCM→play) node. VERIFY: QEMU `-audiodev wav,path=out.wav` capture → assert
   non-zero samples. Multi-PR (one of the most complex virtio devices). No ALSA/
   Pulse/PipeWire userspace yet either.
2. **Mouse/pointer + USB HID** — drain.rs already push_event0's ALL event types,
   but only a virtio-KEYBOARD is wired + the evdev node advertises kbd-only caps.
   Add a virtio-tablet/mouse QEMU device + a 2nd evdev node (event1) with
   EV_REL/EV_ABS/BTN_* caps. VERIFY is the hard part (needs QMP input-send-event
   pointer injection — the serial boot-smoke can't do it). USB HID stack absent.
3. **Ethernet beyond virtio-net** — e1000/rtl8139 PCI drivers. Bounded but
   oxide "DHCP" is a static seed, so verifying a 2nd NIC is murky.
4. **3D/virgl + Xorg/Mesa/libdrm userspace** — huge; DRM ioctls (drm/node.rs
   SET_MASTER/GET_MAGIC/atomic-TEST_ONLY) are placeholder; active GPU path is 2D
   scanout only. Many sessions; needs vendor userspace roots (none exist).
5. **Module lifecycle** (modules/lib.rs: load/unload/reloc/signature/refcount),
   **syscall tail** (mostly thin in main dispatch; ~legit per-flag rejections).

Recommended start: AUDIO via virtio-snd (PR1 = driver bring-up to DRIVER_OK +
PCM_INFO/SET_PARAMS/PREPARE/START + a single tone out the tx queue, wav-verified;
PR2 = /dev/dsp + arbitrary PCM; PR3 = capture/mixer).
