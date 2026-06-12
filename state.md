# state — session hand-off

Branch: **main**. Branch counters now live in `metadata/index.md` (AUTHORITATIVE —
read+bump per branch). Dev loop: `tools/boot-smoke-probe.sh x86 <probe>` under
`OXIDE_QEMU_KVM=1` (~20s). **GOTCHA: never `pkill -f qemu-system`** — it matches
the bash-tool's own cmdline and SIGTERMs the shell (exit 144). Use
`pkill -9 -x qemu-system-x86_64`.

## This run (linux2.md loop — "is this the Linux way", no fakes)

PID identity fully unified on the VPID (user-facing pid == vtgid/vtid; internal
tid is kernel-only). Landed + boot-verified (pid_identity_probe PASS x86,
pgid=8 sid=7):
- B112–B116 (prior): fork/wait/getpid/gettid/getppid/kill/sched/prlimit/ptrace/
  affinity/priority/rt_sigqueue/pidfd/proc-self all resolve via `resolve_user_pid`.
- **B117 #1806** SIGCHLD siginfo: real si_pid(child VPID)/si_status/si_code via
  per-parent child_sigq; SA_SIGINFO handlers now correct (sigchld_probe PASS).
- **B118 #1805** pgid/sid in VPID space (with_vpid spawn re-seeds to vtgid; forks
  inherit via clone; kthreads keep internal tid) + /proc/loadavg last_pid via
  live_vpids (pid_identity_probe extended, PASS).
- **B119 #1807** real TCXONC output flow control (TCOOFF/TCOON park/wake; pty
  out_hold reuse; bad action EINVAL) — replaced `TCXONC=>0` (tcflow_probe PASS).

All three boot-verified on merged main x86.

## OPEN — 3 agents running (build-only, worktrees; collect → boot-verify → PR/merge)

1. **F438-io-uring-register** — real io_uring_register: REGISTER_BUFFERS/FILES/
   EVENTFD/PROBE + READ_FIXED/WRITE_FIXED + IOSQE_FIXED_FILE. Replaces
   `427 sys_io_uring_register {0}`. Probe: io_uring_reg_probe.
2. **B120-tty-ioctl-defake** — TIOCMSET/MGET/MBIS/MBIC (pty→ENOTTY; serial/VT→
   real modem bitmask) + TIOCSPTLCK/GPTLCK real pts lock (default locked,
   slave-open EIO while locked). Probe: tty_ioctl_probe.
3. **F439-netlink-multicast** — real bind() nl_groups + NETLINK_ADD/DROP_MEMBERSHIP
   + rtnl_multicast broadcast of RTM_NEWLINK/NEWADDR/NEWROUTE to subscribed
   sockets. Replaces `netlink_fd::bind {0}`. Probe: nlmcast_probe.

**Merge order:** each agent wires the same 3 rootfs files (rootfs_lists.rs,
rootfs.rs put-list, oxide-smokes.sh) → trivial 1-line list conflicts on 2nd/3rd
merge; resolve by keeping ALL probe names. **Bump index.md per branch** (F438→
F next=439; F439→440; B120→B next=121) inside that branch's PR. Boot-verify each
probe on x86 after merge (arm lockstep batch at end).

## First command next session

    cat /tmp/claude-1000/-home-nd-oxide2/*/tasks/ab85a5a9b438cd6d4.output | tail   # io_uring agent result
    # then for each returned branch: checkout, merge main, fix list conflict,
    # bump metadata/index.md, spec-lint, push, PR, merge, boot-smoke-probe x86 <probe>

## linux2.md remaining (validated real gaps, not yet started)
§2.6 full rtnetlink for iproute2/networkd · §2.8 ext4 deep extent trees · §2.9
stale NotImplemented init() shims (iouring/net/tty crates) · §2.10 netfilter RX/TX
enforcement · §2.11 eBPF verifier/JIT · §2.12 tracefs/ftrace real buffers · §2.13
fanotify real semantics · §3 X11/Wayland bring-up. Priority order = linux2.md §7.
