# state — session hand-off

Branch: **B126-dhcp-iface-carrier** (PR pending). Counters in `metadata/index.md`
(AUTHORITATIVE — read+bump per branch). **Dev loop GOTCHA:** the qemu MCP
(`mcp__qemu__qemu_start` arch=x86_64 accel=kvm; then `qemu_continue`,
`qemu_send_serial`, `qemu_serial`) is the RELIABLE boot harness — the
shell `tools/boot-smoke-*.sh` scripts get killed mid-boot when backgrounded
and leave STALE logs (cost hours this session). Build with
`cargo run -p xtask -- grub --arch x86_64 --features debug-boot --build-only`
as a SEPARATE step, confirm `grub: built`, THEN MCP-boot. Never trust a
chained build+boot one-liner. Always verify the ISO mtime is fresh.

## Done this run — real systemd-networkd DHCP, the Linux way (4 kernel bugs)

Replaced the static-IP seed façade with **real vendored systemd-networkd**
obtaining a DHCPv4 lease. PROVEN via MCP: networkd gets DHCP ACK + assigns
`eth0 10.0.2.15/24` + default route via `10.0.2.2` (QEMU user-net server).
Four genuine kernel bugs the real daemon exposed, all fixed the Linux way:

1. **netlink IFLA_CARRIER missing** (`netlink/rtnetlink.rs build_newlink_reply`)
   — every network manager parks at "waiting for carrier" without it. Now
   emits IFLA_CARRIER + operstate from IFF_RUNNING.
2. **root doesn't regain caps on execve for ext4 binaries**
   (`syscalls/execve_common.rs regain_root_caps_at_execve`, called
   unconditionally in `059_execve.rs`) — the old path only ran file-caps via
   `devfs::lookup`, never for real-fs binaries, so a root daemon couldn't
   acquire CAP_SETPCAP. Linux `cap_bprm_creds_from_file` root path.
3. **cap_emulate_setxuid ignored PR_SET_KEEPCAPS** (`sched/cred.rs`) — wiped
   permitted on the root→systemd-network uid drop; networkd KEEPCAPS-retains
   then re-raises. Now gated on `!keep_caps`.
4. **AF_UNIX bound listener leaked on close** (`net/sock_drop.rs` +
   `unix_sock.rs unbind`) — restart-looping daemon hit EADDRINUSE on rebind.
   Now released in InetSocket::Drop.

Plus userspace integration: built `systemd-networkd`/`networkctl` (added to
`vendor/systemd/build.sh` ninja targets + install), `systemd-network` user
(uid 192) in passwd/group/shadow, `.network`+`.service` units (bodies in
`l2_deps.rs`). Static seed REMOVED — `seed_defaults` no longer fakes eth0
(`rtnetlink.rs`); eth0 boots addressless.

## OPEN — networkd auto-start at boot (2 follow-ups)

networkd is built+staged+enabled but NOT yet in default.target Wants (started
by hand it pulls a real lease). Auto-start blocks on:
- **systemd-executor↔PID1 readiness notify**: Type=notify/exec start-op never
  completes — the executor's notify msg carries SCM_RIGHTS fds ("Got extra
  auxiliary fds with notification message"); PID1 closes the fds but the
  service never goes "active" → 90s timeout. Likely an AF_UNIX dgram
  cmsg/SCM_RIGHTS gap on the notify path.
- **single-CPU scheduler fairness**: with TimeoutStartSec=infinity networkd
  runs forever but a busy daemon starves the getty (cooperative sched) → no
  login. Needs preemption/fairness or networkd settling (which needs READY).

Boot today is clean (8.5s, login fast) because networkd isn't auto-pulled.

## First command next session
    grep -rn 'SCM_RIGHTS\|cmsg\|notify' crates/kernel/net/src/unix_sock.rs crates/kernel/net/src/sock_io.rs   # executor notify SCM_RIGHTS path
