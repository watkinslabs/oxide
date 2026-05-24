# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 16s + arm smoke 20s green.

## What actually works

- DHCP via udhcpc: lease, ifconfig, route, resolv.conf
- AF_PACKET TX + RX (sockaddr_ll, eth-strip/prepend per type)
- UDP outbound + reply (online_smoke does a real DNS round-trip)
- TCP loopback (lo path closes 3WHS via drain_loopback)
- ARM lockstep on the above

## What is NOT honest

**`tcp_smoke: PASS hits=2` is misleading.** `InetSocket::new_tcp()`
initialises `kind = SockKind::Udp`. `net::sock::connect`'s first
action is `matches!(sock.kind, SockKind::Udp) → return Ok(())`. So
`connect(AF_INET, SOCK_STREAM, …)` returns 0 without doing the
3-way handshake. `tcp_smoke` calls connect, gets rc=0, prints
"connect OK" — but `tcp_connect` was never called, no SYN ever
went out the wire.

This was discovered in F156-tcp-recv (local branch retained).
Several fixes were attempted:

1. New `SockKind::TcpInit` placeholder so SOCK_STREAM doesn't hit
   the SOCK_DGRAM short-circuit. Routes connect into the real
   TCP path.

2. Lock-deadlock fix in `connect`'s local-port allocator —
   `match *sock.local_port.lock() { …, None => { … *sock.local_port.lock() = … }}`
   held the spinlock across an inner re-lock. Latent because
   path (1) was the only way to reach it.

3. F150-style outbound src-IP pick (use iface primary, not
   LOOPBACK) so slirp's NAT can route the reply.

4. Wait-for-3WHS loops (tick_yield variants, sti+spin variants,
   sti+hlt+cli variants).

Result: with (1)+(2)+(3) applied, `tcp_connect` IS called, the
SYN does go out, `[deliver_rx tcp]` confirms the SYN-ACK arrives,
and the TCP state machine transitions to Established. But
`tcp_smoke` itself wedges immediately after `sys_connect` returns
— before printing "connect OK". Even when connect() does no wait
loop at all and returns Ok(()) immediately, userspace doesn't
resume cleanly. Cause is somewhere in the IRQ-exit / schedule
return path; needs proper instrumentation.

### Where to dig
- The wedge is AFTER sys_connect returns Ok to userspace. Print
  `current().tid` in iretq epilogue or sys_write entry to see if
  tcp_smoke's task ever resumes.
- F143 (wait4 missed-wakeup) and F144 (CFS vruntime in voluntary
  schedule) are recent changes that might interact badly with
  IRQs-fire-during-syscall-return.
- The branch `F156-tcp-recv` (local) has the attempt history.

## Open next (priority order)

1. **F156 tcp_smoke post-connect wedge** (above) — gates real TCP.
2. **DNS resolver wiring** (libc res_init) — uses /etc/resolv.conf
   from F147.
3. **AF_UNIX path-lookup via VFS** — F153 materialises the inode;
   `connect(AF_UNIX, path)` should consult the inode's UnixListener
   Arc directly instead of UNIX_REGISTRY string-key lookup.
4. **smoke-arm-dhcp perf** — full chain exceeds 180s on TCG.
5. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd targeted epoll wakes** — large.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main
- **ARM lockstep**: every kernel-side network change verified on
  both `make smoke-{x86,arm}` AND `make smoke-dhcp-{x86,arm}`

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
make smoke-dhcp-x86  # quick: ~16s
```

Then `git checkout F156-tcp-recv` and instrument the iretq path
to find where tcp_smoke wedges after sys_connect returns.
