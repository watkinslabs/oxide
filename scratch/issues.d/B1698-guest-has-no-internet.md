# B1698 — guest has no internet (`make qemu-x86`, GNOME desktop)

User-reported: "there is no network so i cant get to the internet".

## Which stage of the chain is broken

Instrumented single boot, x86_64, `make qemu-x86` topology
(`-netdev user,id=net0` + `virtio-net-pci`), with a `filter-dump` pcap on the
host side of the netdev so both directions are visible.

| Stage | Result |
|---|---|
| interface exists | OK — `2: eth0 <BROADCAST,MULTICAST,UP> mtu 1500 … 52:54:00:12:34:56` |
| address | OK — `inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0` (kernel-seeded) |
| routes | OK — `10.0.2.0/24 dev eth0 … src 10.0.2.15` + `default via 10.0.2.2 dev eth0` |
| ARP request egress | OK — pcap shows `Request who-has 10.0.2.2 tell 10.0.2.15` for every probe |
| ARP reply on the wire | OK — pcap shows `Reply 10.0.2.2 is-at 52:55:0a:00:02:02` 9 µs after each request |
| frame ingress | OK — `/proc/net/dev` eth0 counts one `rx_packet` per reply (`rx: 192 bytes 3 packets` after three pings), `rx_errors=0 rx_dropped=0`. The virtio-net receive path, the NET_RX poll list and the softirq drain are all healthy; instrumenting `rx_poll_for` showed it reaching the used-ring read on every drain. |
| **neighbour binding** | **BROKEN — `ip neigh` → `10.0.2.2 dev eth0 FAILED`, `/proc/net/arp` empty, after every reply had already been received** |
| any IPv4 egress past ARP | never happens — `/proc/net/dev` eth0 `tx` is exactly the router solicitation plus one ARP request per probe; not one ICMP echo left the guest |
| ping gateway | `2 packets transmitted, 0 received, 100% packet loss` |
| DNS | no `/etc/resolv.conf` at all |

Not a QEMU-side or image-side failure: the gateway answers every ARP request on
the wire and the guest receives the answer. The break is between receiving the
reply and binding the neighbour.

Second, independent break found in the same boot (kept separate from the
neighbour defect): NetworkManager enumerates **no** devices — `nmcli device
status` and `nmcli connection show` both print nothing, and NM's own journal
stops after `manager: startup complete` with
`platform-linux: do-change-link[1]: internal failure 5` and no
`(eth0): new Ethernet device` line. So even with ingress repaired there is no
DHCP client, no DNS configuration and no `/etc/resolv.conf`.

## Evidence retained

- `/proc/net/softnet_stat` CPU0 `processed` is non-zero and eth0's `rx_packets`
  tracks the replies exactly, so the frames reach `deliver_ethernet_meta_in`.
- Retracted mid-investigation: an early reading of `rx_packets=0` looked like
  dead ingress. That sample was taken *before* any ARP exchange had occurred —
  nothing had been sent to the guest yet. Ordering the counter read after the
  traffic is what turned the diagnosis around.

## Root cause

`NetStack::deliver_ethernet_l3_in` — the canonical L2 dispatcher every real
driver reaches through `deliver_ethernet_meta_in` — dispatched only `ETH_P_IP`
and `ETH_P_IPV6`. **`ETH_P_ARP` had no arm**, so `deliver_arp_in`, the function
that learns into the per-interface `arp::ArpCache` *and* resumes the transmit
jobs queued on an unresolved neighbour, was reachable only from the
out-of-tree Linux-module netdev shim (`modules/src/linux_netdev/core.rs`).
Machinery without callers.

What ran instead was a **second, parallel neighbour table**: `arp_observe_ethernet`
wrote `NetStack::arp` (a `BTreeMap<(iface, ip), ArpNeighbor>`), whose only
production reader was the bridge transmit path. Nothing on a device transmit
path, and neither `ip neigh`, `/proc/net/arp` nor the ARP ioctls, ever read it.

So an ARP reply was "learned" into a table no consumer of a neighbour reads;
the canonical entry stayed INCOMPLETE and aged to FAILED, and every IPv4 packet
queued behind it was dropped. The guest could ARP but could never follow up.

## Fix

One owner. `ETH_P_ARP` now dispatches to `deliver_arp_in` from the canonical L2
path (direct and bridge-local), and the duplicate `NetStack::arp` table,
`arp_observe_ethernet`, `arp_answer_request` and their accessors are deleted:
the bridge transmit path resolves from the bridge interface's own `ArpCache`,
and `deliver_arp_in` releases the bridge's pending queue as well as the
interface transmit queue.

Two behaviour corrections come with it, both matching the reference:

- A malformed ARP payload is a dropped frame, not an ingress error. The old
  second table swallowed parse failures; the canonical owner returned EINVAL,
  which would have failed the whole L2 dispatch.
- IPv4 ingress no longer teaches the neighbour table. The deleted observer
  learned a binding from any IPv4 frame's source; the reference learns IPv4
  neighbours from ARP.

Pinned by `net::stack::ethernet::arp_ingress_tests` (5 tests). With the ARP arm
removed, 3 of the 5 fail.

## Filed, not fixed by this lane

| Severity | Finding |
|---|---|
| med | `drv-virtio-net`'s `resolve_next_hop_mac_observed` returns `None` for **every** non-broadcast IPv4 next hop, so `NetDev::xmit` with an IPv4 next hop always fails `EHOSTUNREACH`. Its own doc comment claims "IPv4 misses send ARP"; the arm does no lookup and sends nothing. Reached by IPv4 forwarding (`stack_forward.rs`) and IGMP membership reports (`stack_igmp.rs`), so neither can transmit. Not on the path this lane fixed (ordinary socket transmit resolves through `tx_dispatch::resolve_or_queue` and `xmit_l2_observed`). The Linux-shaped repair is to route those `dev.xmit()` call sites through the neighbour-owning dispatch, not to add a second lookup inside the driver. |
| med | NetworkManager enumerates no devices (`nmcli device status` empty; NM journal stops at `manager: startup complete` with `platform-linux: do-change-link[1]: internal failure 5`). The RTM_GETLINK dump itself is fine — `ip -d link` lists `lo` and `eth0` through it — so this is something later in NM's platform layer. Consequence: no DHCP client runs and `/etc/resolv.conf` is never written, so name resolution stays broken even with ARP repaired. |

## Second break on the same chain: outbound IPv4 TTL was 0

With ARP repaired, the verification boot got answers from the gateway for the
first time — and they were `From 10.0.2.2 icmp_seq=2 Time to live exceeded`.

`net::inet_tx::ipv4_ttl` resolved an unset `IP_TTL` (the negative sentinel, the
value every socket has unless a program sets one) to a wire TTL of **0**. The
first router discards such a datagram and answers Time Exceeded, so the guest
could reach its own link and nothing past it. Fixed to the default hop budget
`IPV4_DEFAULT_TTL`; a set value of zero stays zero, and the multicast arm is
unchanged (`IP_MULTICAST_TTL` already defaults to 1 and its setter normalises
the sentinel).

This closes the `known_issues.md` row that recorded the TTL-0 value as "very
likely a divergence" pending verification — it is one, and it was reachable
from `ping` (raw/ICMP send) and every UDP send.
