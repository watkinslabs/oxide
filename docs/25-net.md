# 25 Networking

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`12`,`13`,`16`,`24`,`33`,`34`. Provides:`15` socket syscalls, drivers, eBPF (phase 23).
## 1 Purpose

IPv4 + IPv6 + AF_UNIX + AF_PACKET + AF_NETLINK + AF_VSOCK + AF_XDP. TCP + UDP + ICMP/ICMPv6. Routing, neighbor (ARP/NDP), netfilter-equivalent (basic). Driver model: `NetDev` trait with skb-equivalent buffers.

## 2 Invariants (frozen)

1. Socket fd's `Inode` lives in `/proc/<pid>/fd/<n>`; closed via VFS close path (refcount).
2. Packet buffers (`Pkt`) refcounted; freed when last reference drops.
3. TCP state machine matches RFC 9293 (TCP) state diagram exactly.
4. Each routing decision deterministic given table state (no RNG in lookup).
5. Receive path completes in soft-IRQ (NET_RX); send path may complete in process context or soft-IRQ (NET_TX).
6. No allocation in driver IRQ handler (uses pre-allocated rings).

## 3 Public ifc

```rust
pub trait NetDev: Send+Sync {
    fn name(&self) -> &str;
    fn mac(&self) -> [u8;6];
    fn mtu(&self) -> u32;
    fn xmit(&self, pkt: Pkt) -> KR<()>;
    fn rx_poll(&self, budget: u32) -> u32;     # NAPI-style
    fn ethtool(&self, cmd: u32, arg:&mut [u8]) -> KR<()>;
}

pub fn register_netdev(d: Arc<dyn NetDev>) -> KR<NetIfaceId>;
pub fn route_lookup(daddr: IpAddr) -> KR<RouteEntry>;
pub fn neigh_resolve(iface: NetIfaceId, ip: IpAddr) -> KR<[u8;6]>;
pub fn deliver_rx(iface: NetIfaceId, pkt: Pkt);   # called by driver soft-IRQ
```

## 4 Layers

```
sockets -> proto (tcp/udp/icmp/raw) -> ip4/ip6 -> link (ether/loopback) -> netdev
```

Each layer is a function/trait, not a queueing pipeline. Pkt traverses by direct call. Soft-IRQ NET_RX yields to scheduler at end of budget.

## 5 Pkt buffer

```rust
struct Pkt {
    head: NonNull<u8>,            # base of buffer (page-aligned)
    data: u32,                     # offset of L2 header
    tail: u32,                     # offset of end of payload
    end:  u32,                     # capacity
    len:  u32,                     # data..tail
    refcnt: AtomicU32,
    iface: Option<NetIfaceId>,
    proto: u16,                    # ETH_P_*
    timestamp: Nanos,
    cb: [u8; 48],                  # opaque per-layer scratch (TCP/UDP)
}
```

Allocated from per-CPU slab `pkt_slab` of fixed sizes (256, 1500-MTU, 9000-jumbo).

## 6 Sockets

```rust
struct Socket {
    family: AF, type_: SockType, proto: IpProto,
    state: SockState, ops: &'static dyn SockOps,
    rx_q: PktQueue, tx_q: PktQueue,
    sk_options: SkOptionSet,
    wait: WaitQueue,
}
```

`accept`/`bind`/`listen`/`connect`/`send*`/`recv*`/`shutdown`/`getsockopt`/`setsockopt` go through `ops`.

## 7 TCP

State machine RFC 9293:
- CLOSED, LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT.

Features (frozen):
- Window scaling, SACK, timestamps, ECN.
- TFO (TCP_FASTOPEN).
- Cubic default; BBR available; pluggable congestion control.
- TLP, RACK loss detection.
- TSO/GSO/GRO when driver supports.
- SO_REUSEPORT with per-CPU socket-table sharding.

Tracked as later phases: MPTCP, TCP-AO, zerocopy.

## 8 UDP

UDP + UDPLite. UDP-GRO/UDP-GSO segmentation. SO_REUSEADDR, SO_REUSEPORT. Connected vs unconnected.

## 9 ICMP/ICMPv6

ECHO, DEST_UNREACH, TIME_EXCEEDED, REDIRECT (v4); plus NDP (RS/RA/NS/NA/REDIRECT) on v6.

## 10 Routing

Per-namespace routing tables. Default: main + local. Lookup via LPM trie keyed by dest prefix. Returns `RouteEntry { iface, gateway, src_hint, mtu, metric }`.

`ip route` userspace via netlink (NETLINK_ROUTE).

## 11 Neighbor

Per-iface neighbor cache: `BTreeMap<IpAddr, NeighEntry>`. States: NONE, INCOMPLETE, REACHABLE, STALE, DELAY, PROBE, FAILED. Fed by ARP (v4) / NDP (v6).

## 12 Filtering

We do **not** ship a netfilter clone. Instead: BPF-based hooks at NET_RX/NET_TX (lands with BPF in phase 23). Until then no filtering — incoming non-conntrack packets accepted; outgoing accepted. Full netfilter ride per phase 39.

`iptables`/`nftables` userspace from Fedora needs netlink+netfilter and waits on phase 39. Current acceptance binaries (redis, nginx, openssh) don't need filtering.

## 13 AF_UNIX

Per `24§9`.

## 14 AF_NETLINK

NETLINK_ROUTE: route, link, addr, neigh msgs. NETLINK_GENERIC: name-registered families.

## 15 AF_PACKET

SOCK_DGRAM (no link header) or SOCK_RAW. PACKET_MMAP rings (TPACKETV3). For tcpdump/wireshark.

## 16 AF_VSOCK

Linux vsock with virtio-vsock driver. For VM↔host.

## 17 AF_XDP

UMEM + RX/TX ring. Bypasses sk_buff path. Used by perf-critical net apps. Tracked as later phase.

## 18 Concurrency

- Per-iface RX queue: SPSC; driver IRQ pushes, soft-IRQ pops.
- Per-iface TX queue: MPSC; sockets push, driver consumes.
- Routing table: RCU.
- Socket table per (family,type): RCU + per-bucket spinlock.
- Per-socket spinlock (class `Socket`).

## 19 Perf budget

| Op | p99 cy |
|---|---|
| TCP RX path (NIC IRQ → socket queue) | ≤ 5000 |
| TCP TX path (`send` → device xmit) | ≤ 6000 |
| UDP RX | ≤ 3500 |
| Loopback TCP throughput | ≥ 10 GB/s 4-CPU |
| Connection establish (TCP SYN→ESTABLISHED loopback) | ≤ 30 µs |

## 20 Test contract (frozen)

- Loopback: TCP+UDP RFC tests (tcp-tests harness); all pass.
- virtio-net QEMU: send/recv 1M packets; zero loss, no panic.
- Multi-CPU SO_REUSEPORT: 4 listeners, even distribution within ±5% over 1M conns.
- Property test on TCP state machine: random event sequences (RX/TX/timer/close); state always valid.
- Loom on socket lookup vs close: no UAF.
- iperf3 over loopback: ≥10 GB/s on 4-CPU.
- Acceptance: `nginx` + `curl` get a static page over loopback; over virtio-net.
- Coverage ≥85% (driver paths in QEMU).

## 21 Failure modes

- TCP retransmission exhaustion: ETIMEDOUT on send, or RST→ECONNRESET.
- Allocation failure under pressure: drop packet, increment iface drop counter; never panic.
- Driver xmit error: requeue if recoverable, drop if persistent; mark iface DOWN if N consecutive errors.

## 22 Debug

`debug-net`: per-pkt trace at L2/L3/L4; conn state changes logged; driver ring snapshots.

## 23 Cross-spec

`15` (socket syscalls), `34` (PCIe/MSI for NIC IRQ), `13` (soft-IRQ scheduling), `33` (FW info for MAC at boot if random).

