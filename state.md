# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
x86 smoke 16s + arm smoke 20s green.

## What actually works (post-F156/F157)

- DHCP via udhcpc: lease, ifconfig, route, resolv.conf
- AF_PACKET TX + RX (sockaddr_ll, eth-strip/prepend per type)
- UDP outbound + reply (online_smoke does a real DNS round-trip)
- TCP loopback (lo path closes 3WHS via drain_loopback)
- **TCP outbound through slirp NAT** — real 3WHS to host services:
    `tcp_smoke: 10.0.2.2:22 connect OK`
    `tcp_smoke: 10.0.2.2:22 rx=21 first='SSH-2.0-OpenSSH_9.9`
- ARM lockstep on the above

## What got fixed in this session (F156 + F157)

state.md's prior hand-off blamed the TCP wedge on iretq /
wake-from-IRQ archaeology. That was wrong. Five distinct bugs:

1. **F156:** `InetSocket::new_tcp()` set `kind = SockKind::Udp`,
   so `connect()` short-circuited SOCK_STREAM to "store peer +
   return Ok" without sending a SYN. Added `SockKind::TcpInit`.
2. **F156:** lock-across-match in the ephemeral-port allocator —
   `match *sock.local_port.lock() { … *sock.local_port.lock() = … }`
   self-deadlocked. Hoist guard.
3. **F156:** ANY-bound TCP defaulted local_ip to LOOPBACK for
   off-host destinations. Ported F150's iface-primary logic.
4. **F156:** `virtio-net::modern::rx_poll` held `MODERN_DEV.lock()`
   across cb. cb's TCP path emits an ACK via `tx_frame` which
   re-takes the lock → UP spinlock self-deadlock. UDP/AF_PACKET
   never tripped this (no kernel-side outbound from rx); TCP
   always does (ACK from SYN-ACK). Collect frames under lock,
   drop, dispatch.
5. **F157:** `Inode::read` for TcpConn returned `Ok(0)` for empty
   recv_buf regardless of state — userspace treated as EOF.
   Return `Eagain` unless peer FIN'd.

The `F156-tcp-recv` branch in state.md's prior hand-off was empty
(local work was lost or never committed).

## Open next (priority order)

1. **kernel-side blocking TCP read** — sys_read should consult
   O_NONBLOCK and park on a socket waitq instead of forcing
   userspace into usleep-retry loops. Needs socket waitq plumbing
   (per-conn waitlist, wake on deliver_tcp data delivery,
   wake on FIN).
2. **DNS resolver wiring** (libc res_init) — uses /etc/resolv.conf
   from F147; TCP path now real so dig/host/getaddrinfo can run.
3. **AF_UNIX path-lookup via VFS** — F153 materialises the inode;
   `connect(AF_UNIX, path)` should consult the inode's UnixListener
   Arc directly instead of UNIX_REGISTRY string-key lookup.
4. **smoke-arm-dhcp perf** — full chain exceeds 180s on TCG.
5. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd targeted epoll wakes** — large.

## Diagnostic lesson

state.md's prior "instrument iretq" suggestion would have burned
the session. The actual chain: drop a single klog probe pair
around `tick_yield` showed the wedge wasn't in iretq at all —
it was AT `hlt`. Then probing with `sti+pause+cli` (no yield)
reproduced — proving the wedge fired whenever IRQs were allowed
in, not when a task was switched. From there, walking what an
inbound TCP segment does that UDP doesn't (emit an ACK from RX
context) led directly to the rx_poll spinlock self-deadlock in
~10 minutes. Lesson: probe the cheap diagnostic before
believing the prior session's framing.

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

Then start on kernel-side blocking TCP read (item 1 above) or
pick DNS resolver wiring (item 2).
