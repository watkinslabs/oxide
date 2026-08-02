# B1713 — IPv4 receive-side option-area fill

Cluster: machinery with no caller. This branch takes the receive-side half of
the IP-options rows.

## Rows this PR closes or rewrites

### Rewritten — partially closed

Row opening `IP/IPv6 options still stored-but-unconsumed after B1662a-c:
PKTOPTIONS, IP_RETOPTS receive-side record-route/timestamp fill, and anycast
join/leave (still routed to the multicast helper).`

**Outcome 1 (wire the consumer) for the `IP_RETOPTS` receive-side fill half.**
A delivered IPv4 header's option area is now compiled and PAID before anything
sees it: the record-route slot takes the address this host answered on, the
timestamp slot takes the arrival stamp, and a full timestamp option has its
overflow counter advanced. The filled area replaces the received bytes, so a
raw receiver and the reply area `IP_RETOPTS` echoes carry the same header.
`IP_RECVOPTS` and `IP_RETOPTS` are now two publications of ONE echo pass rather
than a raw-area copy plus a second private parser.

The remaining halves of that row (`PKTOPTIONS`, anycast) are untouched here and
stay open — they are separate mechanisms and get their own lanes.

Row opening `A passive TCP child still carries no IPv4 option area.` names
"receive-side option reversal (record-route/timestamp echo)" as its missing
piece and points at the `IP_RETOPTS` row. That piece now exists at the delivery
layer (`ipv4_options::rx`), but TCP still does not build a child's area from the
incoming SYN, so the row stays open with a narrower reason: the echo pass exists
and is callable; nothing on the listener path calls it.

## What was actually wired

| Piece | Before | After |
|---|---|---|
| Receive-side compile | none — the raw area was copied verbatim | `ipv4_options::area::build_packet`, the packet-present form of the one compile pass |
| Record-route slot | never filled | filled with the address this host answered on, pointer advanced |
| Timestamp slot | never filled | address and/or stamp written per flag nibble, pointer advanced |
| Timestamp overflow | never advanced | advanced when no slot is left; a counter at 15 is a header error |
| Malformed received area | delivered anyway | packet dropped |
| `IP_RETOPTS` | a second private parser in `cmsg::payload` | `ipv4_options::rx::echo` over the compiled area |
| `IP_RECVOPTS` | the raw received bytes | the echoed reply with the echo's own pointer advance retracted |
| Raw4 / ping option area | re-parsed out of the packet bytes | carried on the receive record, like the compiled area a delivered packet owns |

The duplicate parser `cmsg::payload::echo_options` is deleted. There is now one
IPv4 option-area compile pass and one echo pass.

## Positive control

Deleting the fill call in `ipv4_options::rx::received` fails six tests:

    cmsg::tests::the_reply_area_and_the_received_area_are_two_messages_from_one_echo
    ipv4_options::tests_rx::a_prespecified_slot_naming_another_host_is_stamped
    ipv4_options::tests_rx::a_record_route_slot_takes_the_address_the_host_answered_on
    ipv4_options::tests_rx::a_timestamp_and_address_option_records_both
    ipv4_options::tests_rx::a_timestamp_only_option_is_stamped_with_the_arrival_time
    ipv4_options::tests_rx::the_reply_steps_the_record_route_pointer_over_the_slot_it_will_fill

`tests_ipv4_options_rx` proves the wiring end to end: a UDP datagram delivered
through `NetStack::deliver_rx` reaches its socket with the slot filled and the
pointer advanced, and one whose area does not parse reaches no socket at all.

`cargo test -p net`: 1909 before, 1930 after, 0 failed.

## Deviations recorded here

- **Reversed source route, declared length.** Upstream computes the reply
  route's declared length as `4N+7` and subtracts 4 when the lowest recorded
  slot is the sender's own address — so a route whose lowest slot is NOT the
  sender declares four bytes the reply never wrote, read out of an
  uninitialised stack buffer. This declares exactly the hops it carries. The
  two agree in the normal case (the sender's address is what the first hop
  recorded); they differ only in the case upstream leaks bytes.
- **Echo failure sets no `MSG_CTRUNC`.** An area whose record-route or
  timestamp pointer leaves no room for the reply's own slot produces no
  ancillary message at all; upstream additionally flags the control buffer as
  truncated. `cmsg::plan` has no channel for message flags — adding one is a
  `recvmsg` shim change, not an option-area one.
- **A forwarded router-alert packet's option area is not compiled**, so a
  router-alert raw receiver sees an empty area. This stack has no compile pass
  on the forward path at all; the row for that is the IPv4-forwarding one, not
  this.
- **Source-routed receives are not screened.** Upstream refuses a received
  source route unless the receiving interface accepts source routing, and then
  runs a routing pass over it. Neither exists here: the route is compiled,
  recorded and echoed, and never acted on. No `accept_source_route` control
  exists to hang the screen off.

## Rows in the cluster this PR does NOT touch

Owned by live lanes — not opened here:

- `TCP fast-open codec has no production caller` — lanes B1710/B1711/B1712.
- `net.ipv4.tcp_fastopen_blackhole_timeout_sec still does not exist` (two
  rows) and the `TFO_CLIENT_NO_COOKIE` row — same ladder, same lanes.
- `IPv6 sticky extension headers stored-only` — lane B1661.
