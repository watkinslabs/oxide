# B1714 — `IP_PKTOPTIONS` gets a producer and a consumer

Cluster: machinery with no caller. Second lane, after B1713 (receive-side
option-area fill).

## Row this PR rewrites

Row opening `IP/IPv6 options still stored-but-unconsumed after B1662a-c:
PKTOPTIONS, IP_RETOPTS receive-side record-route/timestamp fill, and anycast
join/leave (still routed to the multicast helper).`

**Outcome 1 (wire the consumer) for the `PKTOPTIONS` half.** The option
previously answered a stream socket with an empty byte string — a length of
zero and no messages, indistinguishable to a caller from "this socket recorded
nothing" and therefore the worst kind of inert surface. Nothing anywhere
recorded the values it is supposed to publish.

The `IP_RETOPTS` half closed on B1713. Anycast stays open (below).

## What was actually wired

| Piece | Before | After |
|---|---|---|
| The values | never recorded anywhere | a passive open records the opening IPv4 header's interface, hop limit and service class |
| Where they live | — | the multicast interface index and hop limit fields, plus a new `ip_rcv_tos` — the same three slots the reference reads them out of, so `IP_MULTICAST_TTL` on an accepted socket reports the same value it does upstream |
| `getsockopt(IP_PKTOPTIONS)` | `Ok(Bytes(vec![]))` on a stream socket | a control-message stream: `IP_PKTINFO`, `IP_TTL`, `IP_TOS`, each gated on the receive option that would have produced it per datagram |
| Datagram sockets | `ENOPROTOOPT` | unchanged, and the decision still lives in the value table, not the shim |
| cmsg encoding | one encoder in `recv_control::Control::copy_to` | one `encode_entry` shared by the receive cursor and this read, so the header, the truncation rule and the cursor advance are decided once |

The type-of-service value is an `int` here, not the one-byte form the
per-datagram receive publishes — this option reports a stored value, not a
header field. Pinned by a test.

## Positive controls

- Emptying `sock_opts::record_accepted_header` fails
  `sock::construct::tests::an_accepted_socket_records_what_the_opening_header_carried`.
- `tcp_conn::tests` pins the byte offsets the passive open reads (service class
  at 1, hop limit at 8), that an IPv6 open records nothing at the IPv4 level,
  and that a runt packet records nothing.
- `cmsg::pktoptions::tests` pins which receive option gates which message, the
  order, the packet-info layout, and the `int` width of the service class.

`cargo test -p net`: 1909 before, 1919 after, 0 failed.

## What is NOT pinned by a test

The single call site in `sock::ops::accept` that invokes
`record_accepted_header`, and the `getsockopt` shim arm, are on kernel-gated
paths (`055_getsockopt/ip.rs` carries `#![cfg(target_os = "oxide-kernel")]`).
Both are one-line links between tested pieces. Every decision either side of
them — which values, which offsets, which messages, which errno — is in an
ungated module with tests.

## Deviations recorded here

- **The IPv6 twin is not touched.** `IPV6_2292PKTOPTIONS` reads its own
  header's fields upstream and still publishes nothing here. It is a separate
  mechanism with a separate recording site; this lane is the IPv4 one.
- **A connecting (not accepted) socket publishes the defaults** — a zero
  interface, zero hop limit and zero service class — because nothing records a
  header for an active open. That matches upstream, which also only records
  these at passive open; upstream's multicast hop-limit default of 1 is
  preserved for a socket with nothing recorded, which is why the recorder
  refuses to write when no interface was captured.

## Anycast — still open, with the mechanism named

Row opening `IPV6_JOIN_ANYCAST / IPV6_LEAVE_ANYCAST still route to the
multicast helper` and the `IPv6 anycast` half of the row above.

**Outcome 3.** This is not "stored but unconsumed" — it is worse: joining an
anycast address currently joins a MULTICAST group, so the call succeeds and
does something else. Fixing it is not a wire-up; the mechanism does not exist:

1. No per-device anycast address list with a reference count, so nothing can
   answer "is this destination one this host answers for as an anycast
   address". Multicast has `v6_mcast`; there is no `v6_anycast` beside it.
2. `v6_dst_is_local` / `v6_dst_is_local_in` therefore have nothing to consult,
   which is the consumer that makes a join observable at all.
3. No per-socket anycast list, so a close cannot release the joins a socket
   made — the leak upstream avoids with `ipv6_sock_ac_close`.
4. Joining an anycast address must also join its solicited-node multicast
   group, or neighbour discovery never resolves it.
5. The admission ladder is its own: `CAP_NET_ADMIN` (not the multicast
   screen), `EINVAL` for a multicast address, `EINVAL` for an address this host
   already holds as unicast, a route lookup when no interface is named,
   `EADDRNOTAVAIL` on a host with no matching prefix and no forwarding.

That is a subsystem, not a call-site fix, and it belongs in its own lane with
all five pieces. Leaving the current misrouting in place is not acceptable
either — it is recorded here as the reason the row stays open, not as a
deferral of the decision.
