DRAFT 2026-05-25. Dep: 25, 26.

# Network stack — gap analysis after F195

Audit of network-layer surface after the F156→F195 sweep. Maps
each feature to status: **done** | **partial** | **gap** | **n/a**
(out of v1 scope per docs/03 modernity charter). Apps benchmark
on Linux 6.x; n/a means a Linux feature we explicitly don't ship.

## 1. TCP

| Feature                              | Status   | Notes |
|---|---|---|
| RFC 9293 state machine               | done     | F156 |
| 3WHS (active + passive)              | done     | F157, F160 |
| RFC 6298 RTO + retx                  | done     | F159 |
| TIME_WAIT linger (60s 2*MSL)         | done     | F161 |
| SO_ERROR (errno→fd)                  | done     | F163 |
| SO_SNDBUF / SO_RCVBUF                | done     | F164, F186 |
| TCP_NODELAY / Nagle                  | done     | F175 |
| MSS option negotiation               | done     | F173 |
| Per-iface MTU → advertised MSS       | done     | F184 |
| ICMP unreach → SO_ERROR              | done     | F174 |
| SO_REUSEADDR strict TW conflict      | done     | F176 |
| SO_REUSEPORT load distribute         | done     | F192 |
| listen(2) backlog cap (somaxconn)    | done     | F192 |
| Window scaling (RFC 7323)            | done     | F178, F186 |
| OOO receive buffer                   | done     | F179 |
| SACK emit + consume + retx-skip      | done     | F179a |
| RFC 7323 Timestamps + PAWS           | done     | F182 |
| Slow-start / IW=10                   | done     | F185, F187 |
| Fast retransmit (3 dup-ACKs)         | done     | F185 |
| Congestion control: Reno             | done     | F185 |
| Congestion control: CUBIC            | done     | F187 (default) |
| ECN (RFC 3168) — negotiate + ECT     | done     | F190 |
| Path MTU Discovery v4 (frag-needed)  | done     | F191 |
| Path MTU Discovery v6 (too-big)      | done     | F191 |
| Keepalive probes                     | done     | F193 |
| SO_LINGER abortive close             | done     | F194 |
| TCP_INFO getsockopt                  | done     | F188 |
| TCP over IPv6                        | done     | F180b |
| TCP_KEEPIDLE/INTVL/CNT setsockopts   | gap      | constants honored, options not yet wired |
| SO_LINGER blocking timeout > 0       | gap      | abortive path done; blocking close in sys_close TBD |
| TCP_DEFER_ACCEPT                     | gap      | rarely used; defer until app demand |
| TCP_FASTOPEN (TFO, RFC 7413)         | gap      | cookies + early data; nontrivial |
| TCP_MD5SIG                           | gap      | BGP-only feature |
| ECN-CE wire detection                | partial  | echo path done; we don't sniff incoming IP TOS for CE on data segs (peer-reported ECE drives it) |
| RACK + TLP loss detection            | gap      | improves recovery latency |
| BBR / DCTCP                          | gap      | CUBIC is the Linux default; alternatives are tuning |
| TCP_NOTSENT_LOWAT                    | gap      | epoll-EPOLLOUT shaping |
| SO_BINDTODEVICE                      | gap      | needed for multi-NIC steering |

## 2. UDP / datagrams

| Feature                              | Status   | Notes |
|---|---|---|
| RFC 768 send/recv (v4)               | done     | |
| RFC 768 send/recv (v6)               | done     | F180a |
| Pseudo-header checksum (v4 + v6)     | done     | |
| ICMP unreach → SO_ERROR              | done     | F174 |
| Per-port recv waitqueue              | done     | F162 |
| UDP_CORK / batched send              | gap      | one syscall per dgram today |
| UDP_SEGMENT (USO)                    | gap      | NIC offload variant |
| UDP-Lite                             | n/a      | rarely used |
| MSG_PEEK / MSG_TRUNC / MSG_DONTWAIT  | partial  | MSG_DONTWAIT honored; PEEK/TRUNC TBD |

## 3. AF_UNIX

| Feature                              | Status   | Notes |
|---|---|---|
| SOCK_STREAM pair                     | done     | UnixPair |
| SOCK_SEQPACKET pair                  | done     | UnixMsgPair |
| SOCK_DGRAM bind/recv                 | done     | UnixDgramQueue |
| accept + connect via path registry   | done     | UnixRegistry |
| Per-end shutdown + EOF observation   | done     | F166, F170, F171 |
| SCM_CREDENTIALS                      | done     | F121 |
| SCM_RIGHTS over SOCK_DGRAM           | done     | F189 |
| SCM_RIGHTS over SOCK_STREAM          | gap      | message-boundary tracking in UnixPair |
| Abstract namespace (`@/…`)           | partial  | path lookup ignores leading NUL |

## 4. AF_PACKET / raw

| Feature                              | Status   | Notes |
|---|---|---|
| AF_PACKET registry + recv            | done     | F137, F172 |
| ETH_P_ALL bind                       | done     | |
| ETH_P_<proto> bind                   | done     | |
| AF_PACKET TX (sendto)                | done     | |
| PACKET_MMAP / TPACKET_v3             | gap      | mmap ring buffer; rarely needed by apps |
| SOCK_RAW (IPPROTO_*)                 | partial  | shapes wired in net.rs; data path stubbed |
| IP_HDRINCL                           | gap      | needed for traceroute, custom IP gen |

## 5. ICMP / ICMPv6 / NDP

| Feature                              | Status   | Notes |
|---|---|---|
| ICMP echo respond                    | done     | |
| ICMP Dest Unreachable → SO_ERROR     | done     | F174 |
| ICMP Frag-Needed → PMTUD             | done     | F191 |
| ICMPv6 echo respond                  | done     | F180a |
| ICMPv6 Packet-Too-Big → PMTUD        | done     | F191 |
| NDP NS responder (own addr)          | done     | F180c |
| NDP NA cache populate (inbound)      | done     | F180c |
| NDP NS outbound on cache-miss        | gap      | needed for off-link v6 unicast |
| Router Solicitation / RA             | gap      | SLAAC config from router |
| MLD (multicast listener discovery)   | gap      | with multicast |
| Redirect message                     | gap      | rare; mostly disabled in Linux |

## 6. Routing & forwarding

| Feature                              | Status   | Notes |
|---|---|---|
| RouteTable add/lookup (v4)           | done     | longest-prefix-first |
| Loopback default route               | done     | |
| IPv6 route table                     | gap      | currently uses "lo for ::1 else first iface" |
| ECMP multipath                       | gap      | |
| Policy routing / `ip rule`           | gap      | |
| Routing socket (NETLINK_ROUTE)       | partial  | rtnetlink crate exists; not all RTM_* served |
| IP forwarding (sysctl net.ipv4.ip_forward) | gap | host-mode only today |

## 7. ARP / neighbor table

| Feature                              | Status   | Notes |
|---|---|---|
| ARP request/reply                    | done     | |
| ARP cache with stale GC              | done     | F177 |
| ARP probe / proxy_arp                | gap      | |

## 8. Sockopts

| Level    | Option              | Status | Notes |
|---|---|---|---|
| SOL_SOCKET | SO_REUSEADDR      | done   | F176 |
| SOL_SOCKET | SO_REUSEPORT      | done   | F192 |
| SOL_SOCKET | SO_KEEPALIVE      | done   | F193 |
| SOL_SOCKET | SO_BROADCAST      | done   | stored, UDP honors |
| SOL_SOCKET | SO_SNDBUF/RCVBUF  | done   | F164, F186 |
| SOL_SOCKET | SO_SNDTIMEO/RCVTIMEO | done | F167 |
| SOL_SOCKET | SO_ERROR          | done   | F163 |
| SOL_SOCKET | SO_LINGER         | done   | F194 (abortive only) |
| SOL_SOCKET | SO_PRIORITY/MARK  | partial | stored, not data-path enforced |
| SOL_SOCKET | SO_BINDTODEVICE   | gap    | |
| SOL_SOCKET | SO_PASSCRED       | partial | creds emitted via SCM_CREDENTIALS unconditionally |
| IPPROTO_TCP | TCP_NODELAY      | done   | F175 |
| IPPROTO_TCP | TCP_INFO         | done   | F188 |
| IPPROTO_TCP | TCP_CORK         | gap    | |
| IPPROTO_TCP | TCP_KEEPIDLE/INTVL/CNT | gap | constants honored, options not parsed |
| IPPROTO_IP | IP_TTL            | gap    | hard-coded default |
| IPPROTO_IP | IP_TOS            | gap    | ECN goes via TCP path |
| IPPROTO_IP | IP_PKTINFO        | gap    | cmsg writeback on recv |
| IPPROTO_IPV6 | IPV6_V6ONLY     | gap    | currently both families share state |

## 9. IPv6

| Feature                              | Status   | Notes |
|---|---|---|
| IPv6 header parse/emit               | done     | |
| ICMPv6 echo + PMTUD                  | done     | F180a, F191 |
| UDP over IPv6                        | done     | F180a |
| TCP over IPv6                        | done     | F180b |
| NDP cache + NS responder             | done     | F180c |
| AF_INET6 dual-stack mapped binds     | done     | sock.rs |
| Fragmentation extension header       | gap      | tied to outbound fragmentation |
| HBH / Routing / DestOpts ext headers | gap      | |
| Flow label                           | gap      | |
| SLAAC (RA processing)                | gap      | with NDP RS/RA |

## 10. IP layer

| Feature                              | Status   | Notes |
|---|---|---|
| IPv4 inbound reassembly              | done     | F195 |
| IPv4 outbound fragmentation          | gap      | currently DF=1 + rely on PMTUD |
| IPv6 inbound reassembly              | gap      | with v6 fragment extension hdr |
| IPv6 outbound fragmentation          | gap      | |
| IP_MULTICAST_*                       | gap      | |
| IGMP / MLD                           | gap      | |

## 11. Performance / observability

| Feature                              | Status   | Notes |
|---|---|---|
| Per-fd targeted epoll wake           | done     | F181a |
| TCP_INFO struct                      | done     | F188 |
| Per-conn stats counters              | partial  | retx_q + ka_count tracked; rx/tx byte counters TBD |
| /proc/net/tcp + /proc/net/udp        | gap      | |
| ss / netlink-sock-diag               | gap      | |
| eBPF / XDP / TC                      | n/a      | huge subsystem, real Linux distros work without it |

## 12. Out of v1 scope (per docs/03)

- DCCP / SCTP / MPTCP / QUIC at this layer (QUIC is userspace)
- IPsec (transport / tunnel) — separate subsystem; rides on its own crate later
- WireGuard — userspace tools work over UDP without kernel module
- Network namespaces — `00§3` master plan defers to a later phase
- bridge / VLAN / VRF — same
- Conntrack / NAT — netfilter has hook stubs but no module yet
- GSO / GRO / LRO offloads — NIC-side, deferred

## Recommended next pulls (impact-ordered)

1. **NETLINK_ROUTE completeness** (RTM_GETLINK / NEWADDR / GETROUTE)
   — every userspace network tool reads these (`ip`, `networkd`,
   `NetworkManager`). High impact for "real distro programs work."
2. **SCM_RIGHTS over SOCK_STREAM** — systemd socket-activation,
   docker, X server all need it on stream sockets.
3. **IPv6 fragmentation** (in + out) — mirror of F195 for v6.
4. **TCP_KEEPIDLE/INTVL/CNT setsockopts** — small, frees apps to
   tune keepalive without sysctl.
5. **SO_BINDTODEVICE** — needed for any multi-NIC deployment that
   wants per-iface socket pinning.
6. **IPv4 outbound fragmentation** — close the symmetry with F195.
7. **AF_NETLINK sock_diag** — needed for `ss` / monitoring agents.
8. **IPv6 route table** — flat lo/first-non-lo heuristic suffices
   until we have a second v6-capable iface.
9. **SLAAC (RS + RA)** — autoconf for v6 networks without DHCPv6.
10. **MLD** — required for v6 multicast groups (mostly host LL).

Items beyond #10 are tuning/perf or rare-app territory.
