# state.md — session hand-off

## Headline
N22 ROOT CAUSE DEFINITIVELY ISOLATED (evidence-backed, all prior theories
disproved): **udev never processes eth0** → no `/run/udev/data/n<ifindex>` →
NetworkManager treats eth0 as unready/unmanaged → never activates/DHCPs it →
host SSH-forward to 10.0.2.15:22 times out. The fault is in the sysfs/udev
**coldplug uevent enumeration for net devices**, NOT netlink, NOT the IP-seed,
NOT the IFF flags. 9 PRs merged this session; main @ b51976f5b.

## N22 evidence chain (instrumented boots, `debug-boot debug-netlink`)
The `[NL-GETLINK]`/`[NL-SETLINK]` trace (merged, PR#3891) proved, every boot:
1. `[NL-GETLINK ns=0 n=2 ifidx=1:lo ifidx=2:eth0]` — the RTM_GETLINK dump DOES
   contain eth0. NM receives it. (kills netlink/ns/dump theories.)
2. `[NL-SETLINK ... ifidx=1 ...]` ONLY — NM never sends a setlink for eth0
   (ifidx 2). It has the link but builds no device / never activates it.
3. Log has NO `/run/udev/data/n2`, NO `SUBSYSTEM=net`, NO `INTERFACE=eth0` —
   **udev never processed eth0.** NM depends on udev device readiness, so it
   leaves eth0 unmanaged. THIS is N22.

## Disproved this session (do not re-open)
- IP-seed hack (`pci-boot` hardcoded 10.0.2.15/24): removed it → NM behaved
  IDENTICALLY. NOT the cause. (Seed is still a real split-truth to remove, but
  only AFTER DHCP works — removal alone regresses guest to no-network.)
- Hardcoded `IFF_UP` at registration: removed it (eth0 → fl=4162 admin-down) →
  NM STILL never touched eth0. NOT the cause.
- netlink dump/delivery/ack/ns: all proven Linux-correct (recvmsg honors
  MSG_TRUNC/PEEK; build_ack echoes seq; enqueue wakes waiters; all ns=0).
- Empty `DEVTYPE=` in net uevent: real bug, FIXED (B1380/PR#3892), but boot
  showed it alone does NOT unblock udev.

## FIRST TASK next session (decisive, one instrumented boot)
Instrument the coldplug path to see WHY udev skips eth0. Add debug klogs:
1. `sysfs/src/lib.rs` `NetIfaceData::store` — log when the net `uevent` attr is
   WRITTEN (does `systemd-udev-trigger` coldplug reach eth0's uevent?).
2. `SysDevicesVirtualNetOps::iterate` + the `/sys/class/net` iterate — log when
   the net dir is walked (does coldplug enumerate net at all?).
Then ONE `debug-boot` conformance boot. Two outcomes:
- store NEVER written → coldplug isn't reaching net. Likely gaps: **no
  `/sys/subsystem/net/devices/`** (modern systemd-udev-trigger enumerates via
  `/sys/subsystem/<sub>/devices/`; Oxide has NO `/sys/subsystem/*` at all — grep
  clean), or `/sys/class/net` not enumerable the way udev expects. Compare to
  the DRM/card0 path that DOES get coldplugged.
- store IS written but udevd still skips → inspect the emitted env/SEQNUM vs
  what udev's net rules need; or udevd worker failing on net.

## Merged this session (9 PRs, all both-arch built)
- B1373 (#3886) unbreak net plain host build (bind_file cfg) + input test fix.
- B1374 (#3887) net iface `subsystem` → /sys/class/net symlink.
- B1375 (#3888) rtnetlink notifier before netdev register + getlink coverage test.
- B1376 (#3889) IPV6_TCLASS + IPV6_RECVTCLASS full TX/RX wiring (agent).
- B1377 (#3890) rtnetlink neighbor family GETNEIGH/NEWNEIGH/DELNEIGH (agent).
- B1379 (#3891) debug-netlink RTM_GETLINK/SETLINK trace (the N22 cracker).
- B1380 (#3892) drop malformed empty DEVTYPE= from net uevent.

## Parked branch: B1378 (local, unmerged, DO NOT delete)
`B1378-remove-boot-ip-seed-hack`: removes the IP-seed + registers ether devices
admin-DOWN + AF_PACKET-TX tests bring iface up. All Linux-correct, net 981/981.
BLOCKED: can't merge until udev/DHCP works (removing the seed regresses guest to
no-network). Resume AFTER the udev coldplug fix lands. Orthogonal to N22.

## Green baseline / tooling
`cargo test -p net --features hosted --lib -- --test-threads=1` = 981/981
(needs --test-threads=1). netlink 126, sysfs 64, syscalls 166. Both arches build.
Boot: `OXIDE_QEMU_SSH_PORT=<free> OXIDE_QEMU_FEATURES="debug-boot debug-netlink"
bash tools/oxide-conformance-ssh.sh x86_64 t_mmsg 180` → log `/tmp/oxide-
conformance-*.log`. MCP serial-read broken; use the harness log. Memory: N22 is a
tar pit — instrument, don't boot-per-hypothesis (this session hit that limit).
Counters: B next=1381 (metadata/index.md).
