# state.md — session hand-off

## Headline
Network Linux-parity + hygiene pass. Landed 2 PRs this session; N22 (guest
conformance channel: no DHCP → SSH-forward timeout) RE-DIAGNOSED again — the
subsystem-symlink fix was necessary but NOT sufficient. New firm finding: the
virtio `eth0` IS registered into the initial-ns iface registry, yet NM sees
only `lo`. Root cause is now in the netlink `RTM_GETLINK` path or a boot-time
net-namespace id mismatch, NOT udev/sysfs classification.

## Merged this session
- **PR#3886 (B1373)** unbreak plain host build of `net`: `unix_sock::bind_file`
  + its re-exports referenced cfg-gated `crate::sock` unconditionally → `net`
  failed to build in the plain host config (E0432/E0433), which blocked
  `cargo test -p sysfs`. Gated `bind_file` to the same cfg as `sock`
  (`any(oxide-kernel, test, feature="hosted")`). Also fixed a stale short
  DEVPATH in the input-uevent test find-predicate (masked while net didn't
  build). net plain build clean; net 979/979; sysfs 64/64; both arch kernels build.
- **PR#3887 (B1374)** net iface `subsystem` symlink → `/sys/class/net`: real
  Linux `net_class` parity. NetIfaceOps lookup+readdir now expose it so udev can
  classify SUBSYSTEM=net. Necessary but did NOT close N22 (see below).

## N22 ROOT CAUSE FOUND (this session) — boot-time IP-seed = split source of truth
Two source-only agents converged. NM-root-cause agent PROVED (source) the ns
keying is correct: eth0, lo, and NM's netlink socket all resolve to net-ns id 0;
the `RTM_GETLINK` dump MUST include eth0 (hypotheses a/b/c/d all refuted). The
real cause is upstream: **`crates/kernel/pci-boot/src/lib.rs:187-199` hardcodes
the guest IP `10.0.2.15/24` + default routes onto the virtio-net iface at boot**
(comment: "the QEMU user network contract is the boot-time v1 network identity")
AND `netdev/registration.rs:48-52` hardcodes `IFF_UP|IFF_RUNNING` on every iface.
→ NM sees an interface already UP+RUNNING with exactly the IP DHCP would assign →
treats it as externally-configured → never manages it → no DHCP → N22.
This is a **mandate violation** (docs: no split source of truth, no "v1" subset,
no hacks). The Linux way: kernel registers the NIC with carrier-driven flags;
userspace (NM + DHCP against qemu's 10.0.2.2 server) configures it.

### Why NOT yanked this session (foundation-first, HARD)
Removing the seed before NM/DHCP works end-to-end leaves the guest with NO
network (strictly worse), and one boot LIES about the result (memory:
intermittent). Correct sequence: (1) make DHCP work end-to-end + verify over N
boots, (2) THEN remove the seed + fix IFF flags to carrier-driven. The
conformance SSH harness also connects to 10.0.2.15:22, so removal must be staged
with the harness. This is the TOP next item — a dedicated boot-verified effort,
not a reckless yank onto green main.

### Two real source-provable netlink Linux-parity bugs (fix regardless of N22)
- Netlink dump enqueued as ONE datagram; `receive.rs:233-240` `read()` copies
  `min(len,buf)` and DISCARDS the remainder. Linux delivers a dump across
  multiple recvmsg ending in NLMSG_DONE, never silently truncating. (Low impact
  at 2 ifaces but non-Linux.) Fix: message-granular read that preserves unread
  nlmsg. Coverage gap: no test registers a non-lo dev in ns 0 + asserts it in
  the RTM_GETLINK dump (agent predicts it PASSES — exonerating dump/ns keying).
- `kmain` installs `set_notifier` AFTER PCI enumeration → eth0's boot
  RTM_NEWLINK multicast is dropped. Fix: install notifier before
  init_network_and_pci.

## N22 — earlier refined diagnosis (superseded by root cause above)
Debug-boot conformance boot AFTER B1374 (`OXIDE_QEMU_SSH_PORT=24137
OXIDE_QEMU_FEATURES=debug-boot bash tools/oxide-conformance-ssh.sh x86_64 t_mmsg
180`, log `/tmp/oxide-conformance-PDWabZ.log`):
- virtio-net probes + registers: `probe_child ok=1 rx_bufs=8`. eth0 IS in the
  initial-ns registry (source: `drv-virtio-net/src/modern/netdev.rs::register_netdev`
  → `prepare_iface`+`publish_iface` into `net_ns::initial_namespace()`; probe
  aborts on failure at `modern/state.rs:147`).
- NM (real Fedora NM 1.52) logs ONLY `platform-linux: do-change-link[1]:
  internal failure 5` (that's lo, ifindex 1) then `startup complete`. NEVER
  discovers eth0.
- NM's device list comes from the kernel `RTM_GETLINK` netlink dump, NOT udev.
  `RTM_GETLINK` → `netlink/src/rtnetlink/dumps.rs::handle_getlink_in(ns,hdr)` →
  `ifaces_snapshot_in(ns)` → `stack.ifaces.snapshot_in_ns(ns)`.
- So the bug is: NM's RTM_GETLINK dump returns only lo though eth0 is registered.
  Prime suspects (an investigation agent is source-tracing these, no booting):
  (a) net-namespace id mismatch — the ns a NETLINK_ROUTE socket captures vs
      `initial_namespace()` id the driver registered eth0 into (compare to where
      lo is registered — lo shows, eth0 doesn't).
  (b) multipart dump truncation in `handle_getlink_in` (stops after lo).
  (c) eth0 omitted by a flag/carrier/down filter in the snapshot or per-iface
      RTM_NEWLINK builder (`dumps.rs`).

## FIRST TASK next session
Read the two agent reports (NM-root-cause + net-parity-audit) — results were
being folded in when this hand-off was written. Fix the RTM_GETLINK/ns root
cause (prefer a HOSTED test that registers a non-lo netdev into the initial ns
and asserts it appears in the dump — verifiable without booting). Then work the
ranked net-parity gap list.

## Open network parity items (pre-existing, from prior audit)
- config-change MSI-X vector + live carrier (F_STATUS read; msix_cfg is NO_VECTOR).
- extended virtio feature negotiation (CTRL_VQ/MRG_RXBUF/MTU/MQ/offloads).
- dead IPv4 ARP stub in `net/.../neighbor.rs` (net stack pre-resolves L2).
- (audit agent is producing a fuller ranked list.)

## Tooling notes (read before booting — cost real time)
- MCP serial-READ is broken (`qemu_serial` empty). Use the conformance harness;
  its log IS readable (`log=/tmp/oxide-conformance-*.log`). Timeout arg ≤180.
  Pin `OXIDE_QEMU_SSH_PORT` to a known-free port (checked 24101/24137/24159/24173
  free this session). `debug-boot` feature exposes net/udev; `debug-sshd` hides it.
- Memory: N22 guest channel is a multi-session tar pit — advance network via
  host-oracle+source, do NOT boot-per-hypothesis.

## Green baseline
`cargo test -p net --features hosted --lib -- --test-threads=1` = 979/979
(2 ARP-proxy tests fail ONLY in parallel — need --test-threads=1). sysfs 64/64.
Both arch kernels build. main @ c8e20e82b (after PR#3887 merge).

## Git hygiene (this session's discipline — keep it)
Branch per change off fresh origin/main → commit → push -u → gh pr create →
gh pr merge --merge --delete-branch → checkout main + pull --ff-only. Bump the
matching counter in metadata/index.md (B is at 1374 next). Author
Chris Watkins <chris@watkinslabs.com>, no Co-Authored-By trailers.
