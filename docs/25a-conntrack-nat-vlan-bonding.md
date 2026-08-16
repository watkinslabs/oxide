# 25a Conntrack, NAT, VLAN, bonding

FROZEN 2026-08-16. Dep:`01`,`02`,`06`,`25`,`26`,`52`.
Provides: stateful filtering for `26§7` nftables, `ip link` VLAN and bond kinds.

## 1 Purpose

Connection tracking, network address translation, 802.1Q VLAN interfaces, and
link bonding. Supersedes `25§12`, which predates the netfilter substrate.

## 2 Invariants (frozen)

1. A tracked flow is reachable under **both** its tuples. A NAT binding rewrites
   one of them, so a reply is matched against the tuple it actually carries.
2. A tuple compares on src, dst, l3num, protonum and zone. No field is optional.
3. An entry is published to the table only after the hooks accept its first
   packet. A dropped first packet leaves no entry.
4. A NAT binding is decided once, on the first packet, and replayed thereafter.
5. A reply is translated by the **opposite** manipulation to the one the flow was
   bound with.
6. Sequence comparisons are modulo 2^32 throughout.
7. Every tracker decision is a pure function of the segment, the recorded state
   and the tunables: no tracker reads global time or a packet buffer.
8. A VLAN interface is an ordinary netdev in the one interface registry. There is
   no second registry; the tag-to-interface map is an index, not a source of truth.
9. A bond master is likewise an ordinary netdev; slaves remain registered.

## 3 Tuple and table

| Concept | Shape |
|---|---|
| Tuple | `{src:{addr,proto}, dst:{addr,proto}, l3num, protonum, zone}` |
| Port protocols | `proto.port` is the port, host order |
| ICMP | `src.proto.port` is the id; `dst.proto.{icmp_type,icmp_code}` |
| Table hash | whole tuple, Jenkins over the address words plus ports, type/code, protocol, family, zone |
| NAT source hash | source end plus protocol only, so one client collides into one bucket |

Inversion swaps the ends. An ICMP type with no reply form has no inverse and
cannot open a flow (`§4.3`).

Confirmation checks both tuples under their own buckets and inserts under both.
Two flows may share neither an original nor a reply tuple.

## 4 Protocol trackers

### 4.1 TCP

States `NONE, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT, CLOSE_WAIT, LAST_ACK,
TIME_WAIT, CLOSE, SYN_SENT2`, plus the table sentinels `MAX` (invalid) and
`IGNORE`. Transitions are a `[direction][flag class][state]` table; the flag
classes are `syn, syn|ack, fin, ack, rst, none` with RST taking precedence.

Timeouts, seconds: SYN_SENT 120, SYN_RECV 60, ESTABLISHED 432000, FIN_WAIT 120,
CLOSE_WAIT 60, LAST_ACK 30, TIME_WAIT 120, CLOSE 10, SYN_SENT2 120, RETRANS 300,
UNACK 300. The armed timeout is shortened by, in order: retransmissions at or
above the limit, a RST, unacknowledged data, a zero window.

Window tracking maintains per direction `td_end`, `td_maxend`, `td_maxwin`,
`td_maxack`, `td_scale`. A segment is refused when its sequence is past the
right edge or it acknowledges data the peer never sent; it is ignored when it is
below the left edge or its ACK is implausibly delayed. Liberal mode converts
every refusal into an accept.

Window scaling applies only when both directions announced it.

### 4.2 UDP

Unreplied 30 s, replied 120 s. A replied flow becomes a stream, and assured,
only after two seconds of continued traffic.

### 4.3 ICMP / ICMPv6

Request/reply pairs keyed on the id. Only echo, timestamp, information and
address-mask requests (v4) and echo request and node-information query (v6) may
open a flow. Error messages are RELATED to the flow they quote, never a flow of
their own. Timeout 30 s.

### 4.4 Generic

Any other protocol: 600 s, no state.

## 5 Expectations and helpers

An expectation is `{tuple, mask, master, class, flags, timeout, helper, dir,
saved_addr, saved_proto}`. The mask wildcards address and port fields; family,
protocol and zone are always compared exactly. Expectations hash on the
destination end alone.

Admission: an identical announcement from the same master replaces the old one;
a different class for the same tuple is `EALREADY`; an announcement that cannot
be told apart from an existing one under the intersection of their masks is
`EBUSY`; the per-master class budget and the global ceiling are `EMFILE`.

Helper attachment: an explicit choice (`IPS_HELPER`) is never overridden;
a template naming no helper detaches one; a helper already attached is kept
rather than swapped. Automatic attachment by port is off by default.

## 6 NAT

| Flag | Meaning |
|---|---|
| `MAP_IPS` | rewrite the address |
| `PROTO_SPECIFIED` | the port window is meaningful |
| `PROTO_RANDOM` / `PROTO_RANDOM_FULLY` | skip reuse, randomise the search offset |
| `PERSISTENT` | choose the mapped address from the source alone |
| `PROTO_OFFSET` | offset the port from a base instead of searching |
| `NETMAP` | one-to-one prefix map |

Selection order for a source binding: keep the tuple when it is already in range
and unused; otherwise reuse a prior mapping for the same client; otherwise pick
an address and search for a free port. A random request skips the first two.

Default port window when none is given: source below 512 maps into 1–511,
below 1024 into 600–1023, otherwise 1024–65535. A destination port is never
invented without an explicit range.

The port search is bounded at 128 probes, halving and retrying from a fresh
offset until the budget falls below 16. Below a quarter of the budget it may
evict a flow that is already closing.

Hooks: destination translation at pre-routing and local-out, priority −100;
source translation at post-routing and local-in, priority +100. A manipulation
attached to any other hook is refused at load time.

Masquerade takes the egress interface's address and records the interface; the
binding is stale once the route moves. Redirect targets loopback on the output
path and the receiving interface's address on the input path.

Packet rewriting updates the IPv4 header checksum and the L4 checksum
incrementally. A zero UDP checksum stays zero; a computed zero is written as
all-ones. ICMPv4 has no pseudo-header; ICMPv6 does. SCTP's CRC is never updated
incrementally.

## 7 VLAN interfaces

A VLAN interface is `{real_dev, vlan_proto, vlan_id, flags, ingress map[8],
egress map[16]}`. The TCI is `vlan_id | egress_qos(skb priority)`; the egress
map is keyed by `priority & 0xF` and stores the pre-shifted priority-code point.
Ingress maps the 3-bit code point to the packet priority.

Flags: `REORDER_HDR` (tag carried out of band rather than pushed inline),
`GVRP`, `LOOSE_BINDING`, `MVRP`, `BRIDGE_BINDING`.

Creation validation: a protocol other than 0x8100 or 0x88A8 is
`EPROTONOSUPPORT`; an identifier at or above 4095 is `ERANGE`; an unknown flag
is `EINVAL`; a real device that cannot carry tags or is not Ethernet is
`EOPNOTSUPP`; a duplicate protocol/identifier pair on one real device is
`EEXIST`. MTU is capped at the real device's.

## 8 Bonding

Modes: `balance-rr`, `active-backup`, `balance-xor`, `broadcast`, `802.3ad`,
`balance-tlb`, `balance-alb`.

Transmit selection: round-robin advances every `packets_per_slave` packets;
active-backup uses the active slave; XOR and 802.3ad index a slave array by
`hash % count`, the latter restricted to the active aggregator's ports;
broadcast clones to every usable slave.

Hash policies `layer2`, `layer3+4`, `layer2+3`, `encap2+3`, `encap3+4`,
`vlan+srcmac`, folding the fields each names and discarding the low bit for the
layer-4 policies.

Link monitoring: `UP → FAIL → DOWN → BACK → UP` with `downdelay` and `updelay`
counters, the up-delay skipped when the bond has no usable path. The ARP monitor
validates by `arp_validate` class and requires any or all targets to answer.

Active-slave selection honours a primary and `primary_reselect` of always,
better (speed then duplex) or failure.

An option unsupported in the current mode is `EACCES`, one requiring no slaves
with slaves present is `ENOTEMPTY`, one requiring the bond down while it is up
is `EBUSY`.

## 9 Ownership

| Crate | Owns |
|---|---|
| `crates/kernel/conntrack` | tuples, trackers, table, expectations, helpers, events, tunables, proc/ctnetlink |
| `crates/kernel/nat` | ranges, tuple search, binding, rewriting, masquerade/redirect |
| `crates/kernel/netfilter` | nftables expressions that consume both |
| `crates/kernel/vlan` | VLAN interfaces and their tag map |
| `crates/kernel/bonding` | bond master, modes, monitors, options, LACP |

Dependency direction is one-way: `nat` depends on `conntrack`, `netfilter`
depends on both, and none of them depends on `netfilter`. `vlan` and `bonding`
depend on `net` only.

## 10 Test contract (frozen)

1. Every cell of the TCP transition table, both directions, asserted against the
   documented value.
2. Scripted bidirectional flows: handshake, orderly close, simultaneous open,
   reply reset, reopen from `TIME_WAIT`.
3. Window checks at each bound, including across the sequence wrap.
4. Table: both-direction lookup, a translated reply tuple, a racing confirm,
   a shared original tuple, a shared reply tuple, expiry, garbage collection.
5. Expectation mask matching asserted on the comparison itself, not only through
   the table, so the bucket hash cannot pass a test the compare would fail.
6. NAT: the default port windows, collision-forced reallocation, the bounded
   search giving up rather than duplicating, and eviction engaging only near the
   end of the search.
7. Packet rewriting verified by recomputing each checksum from scratch over the
   mutated packet, and by a round trip restoring the original bytes.
8. Every positive control listed in `§11` confirmed red then green.
9. VLAN: tag insert/strip round trip, demultiplexing to the right interface, and
   every creation errno.
10. Bonding: each hash policy's field sensitivity, the monitor driven tick by
    tick, aggregator selection per policy, and every option-dependency errno.

## 11 Failure modes

| Mode | Guard |
|---|---|
| A packet matches the wrong flow | every tuple field participates in compare and hash (`§3`) |
| Two flows share a wire tuple | both tuples checked and inserted under their own buckets |
| A reply is translated as an original | the manipulation bit is inverted for the reply direction |
| A blind-injected segment is accepted | window bounds, asserted at each edge |
| An unsolicited ICMP reply creates state | only request types may open a flow |
| A stale expectation keeps a hole open | expiry checked at match time, not only at insert |
| A NAT search scans 64k ports in softirq | probe budget bounded and halving |
| A frame is demultiplexed to the wrong VLAN | the tag map is keyed by protocol and identifier |

## 12 Cross-spec

`25` transport and interfaces, `26§7` nftables surface, `52§9` crate ownership.
