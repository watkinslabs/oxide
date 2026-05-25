# state — hand-off

Branch: main (clean). spec-lint clean, 138 net tests pass
(workspace total ~1182), x86 + arm smoke green via pre-push.

## What just landed (this session)

- **F180a** (#1260): IPv6 UDP bind/recv + ICMPv6 echo + per-port
  Udp6RxQueue with poll subs.
- **F180b** (#1261): TCP over IPv6. Endpoint becomes IpAddr-tagged;
  tcp_hdr v6 pseudo-header + parse_ip/build_into_ip dispatch.
  TcpKey/TcpListenKey on IpAddr; v4 + v6 share one demux.
  AF_INET6 connect/listen route through tcp_connect_ip /
  tcp_listen_ip. drain_loopback dispatches by ethertype.
- **F180c** (#1262): NdpCache + per-iface IPv6 address registry.
  deliver_rx_ipv6 NS arm replies with solicited NA when target
  is owned; NA arm populates cache. 3 hosted tests.

Plus prior session in-flight: F181a per-fd targeted epoll wake.

## Open

Master plan `00§3`: phase 8 (net) shipping ongoing. Remaining
tier-3 / perf items:

1. Real per-iface MTU lookup (OWN_MSS currently fixed 1460).
2. Recv-buf autotune + OWN_WSCALE > 0 for high-BDP.
3. Congestion control (Reno → CUBIC).
4. F180c follow-on: outbound v6 unicast to off-link neighbors
   should consult NdpCache + emit NS on miss. Cache + responder
   are in place; send_l4_over_ipv6 still skips L2 because lo is
   the only registered v6 path today. Lifts naturally once a
   non-lo v6-capable iface exists.

## First task next session

Pick (4) or (1). For (4): extend `send_l4_over_ipv6` to look
up neighbor MAC in `stack.ndp` when iface != lo, queue an NS
solicitation on miss, stash the packet for re-emit on NA
arrival. Tests construct a hosted virtio-style iface and
verify NS emit + retry.
