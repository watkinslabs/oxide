# state — hand-off

Branch: main (clean). spec-lint clean, 1151 hosted tests pass,
both arches build, x86 smoke 14s + arm smoke 20s green.

## Session tally (PRs #1199–#1206)

| PR    | What |
|-------|------|
| F137  | AF_PACKET RX delivery into bound sockets (virtio-net tap → PACKET_REGISTRY → recvfrom queue). |
| F138  | SIOCSIFADDR propagates new IPv4 into virtio-net rx softirq's ARP responder IP. |
| F139  | recvfrom fills sockaddr_ll (family, proto be, ifindex, hatype, pkttype, halen, src MAC) on AF_PACKET sockets. |
| F140  | af_packet_smoke exercises the RX path via recvfrom(MSG_DONTWAIT). |
| F141  | Switch v1 DHCP client from upstream dhcpcd 10.3.2 to busybox udhcpc (already in vendored busybox). |
| F142  | AF_INET / AF_INET6 + SOCK_RAW admitted as UDP shells (ioctl-handle usage). |
| F143  | wait4 missed-wakeup race: post-park reap recheck + unpark_self_from_wait4. Bites every fork+exec+wait4(specific-pid) flow on a fast-exiting child. |
| D34   | state.md hand-off snapshot mid-session. |

## DHCP-stack status

| Stage | Status |
|-------|--------|
| AF_PACKET socket/bind/sendto | ✅ F131/F135 |
| AF_PACKET RX delivery        | ✅ F137 |
| AF_PACKET sockaddr_ll fill   | ✅ F139 |
| AF_INET SOCK_RAW (ioctl handle) | ✅ F142 |
| SIOCSIFADDR → ARP responder IP | ✅ F138 |
| wait4 fast-child race        | ✅ F143 |
| dhcpcd 10.3.2                | ✅ reaches login; wedges post-lease-setup |
| udhcpc launch (OXIDE_UDHCPC_ENABLE=1) | ❌ boot wedges at CAT smoke output; image-layout-dependent |

## Open: udhcpc boot wedge

Repro: build with `OXIDE_UDHCPC_ENABLE=1`. Boot stops cleanly at
the CAT smoke output (`Linux version 5.15.0-oxide…PREEMPT`) and
never produces "init-fork-exec works" from rcS. Without the marker,
boot reaches login in 16s. The marker adds one 2-byte file to /etc
and re-runs mkfs.ext4 — the kernel doesn't read the marker, yet
boot is image-layout-sensitive. Same wedge bites the dhcpcd marker.

Possible causes (untested):
- /sbin/init inode reordering after marker bumps /etc dir entry
  count; kernel ext4 reader returns stale/wrong inode.
- Some early kernel probe that runs the ext4 readdir and pages
  in a now-different block of /etc.
- The kernel-spawned CAT smoke's final exit→spawn-init transition
  is sensitive to free-frame ordering.

Next: bisect by staging the marker file with content sizes that
shift inode allocation (zero-length, exactly-block-aligned),
and check whether the wedge correlates with /sbin/init's inode
number landing in a different ext4 block group.

## Open next (priority order)

1. **udhcpc boot wedge** (above) — DHCP can't actually execute
   until this clears.
2. **AF_UNIX socket-path tmpfs materialisation** — F132's
   `chmod`-tolerance is a hack; bind(AF_UNIX) should create a
   socket-type tmpfs inode at the path.
3. **arm tickless idle** — F130's arm path busy-spins. WFI with
   DAIF.I=1 (SVC-syscall invariant) wedged on QEMU virt; need a
   safe daifclr+wfi+daifset pattern that matches CNTV INTID 27
   wake.
4. **K10 eBPF verifier**, **K13 DRM atomic modeset**,
   **per-fd targeted epoll wakes** — big tickets.

## Discipline notes

- Pre-push hook gates kernel-surface pushes — install once per
  clone: `git config core.hooksPath .githooks`
- Never rebase a published branch
- Never delete branches
- spec-lint clean before every commit + PR
- Never commit directly to main

## First task next session

```
git pull && cargo run -p xtask -- spec-lint && cargo test --all 2>&1 | grep "test result" | head -5
make smoke-x86 SMOKE_TIMEOUT=300
make smoke-arm SMOKE_TIMEOUT=300
```

Then pick item 1 (udhcpc boot wedge). Approach:
- Add a klog::write_raw before `spawn_user_blob_with_vpid(init_blob, …)`
  in `kernel/src/smoke/elf.rs` to confirm whether init spawn even
  runs with the marker present.
- If it does run, the wedge is downstream (init's first instruction
  faults somehow under the new image layout).
- If it doesn't run, the orchestrator never returns from its final
  schedule() — debug the wait4 / Zombie reap path with the marker.
