# B1960 — per-family send/receive differential

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 6c1517fc2 | DEFECT | high | Every family that is not AF_UNIX ran the SCM ancillary rule, so a UDP sender's `IP_PKTINFO`/`IP_TTL`/`IP_TOS`/`IP_RETOPTS` were stepped over and dropped while its `SCM_RIGHTS` was refused and its `SCM_CREDENTIALS` was validated against the sender's identity — the reference's answer inverted in both directions | `socket::tests::family_ancillary` (9), guest differential `t_cmsgfam`: pre-branch kernel returns rc=1 for `udp_ip_unknown`/`udp_tos_short`/`udp_ttl_zero` and EINVAL for `udp_rights`, all four wrong | B1960 |
| FIXED 6c1517fc2 | DEFECT | med | `SO_MARK`, `SO_PRIORITY`, `SCM_TXTIME`, `SO_TIMESTAMPING_OLD/NEW`, `SCM_TS_OPT_ID` and `SCM_DEVMEM_DMABUF` were EINVAL on every family | `socket::sockcm::tests` (7), each with a positive control | B1960 |
| FIXED 6c1517fc2 | DEFECT | med | An unconnected AF_UNIX socket with no peer reported EDESTADDRREQ where the reference reports ENOTCONN | guest `t_cmsgfam`: pre-branch `dgram_unconnected errno=89`, oracle 107 | B1960 |
| FIXED 6c1517fc2 | DEFECT | med | An AF_UNIX byte stream given a destination address ignored it; the reference answers EISCONN when connected and EOPNOTSUPP otherwise | guest `t_cmsgfam`: pre-branch `stream_named rc=1` and `stream_unconnected_named errno=97`, oracle 106 / 95 | B1960 |
| FIXED 6c1517fc2 | DEFECT | med | An AF_VSOCK destination was judged by the outer socket variant rather than by connection STATE, so a connect still in flight, or one the peer had already reset, reported "already connected" | `socket::tests::family_ancillary::a_vsock_destination_is_judged_by_state_not_by_the_socket_variant`; positive control RED on the variant-keyed form | B1960 |
| FIXED 6c1517fc2 | DEFECT | low | AF_VSOCK ran an ancillary rule it does not have (the SCM one), so a control buffer could fail a vsock send; and a datagram destination was refused rather than shape-checked, giving EOPNOTSUPP where the reference gives EINVAL | `socket::vsock_addr::tests` (2) | B1960 |
| FIXED 6c1517fc2 | DEFECT | med | An IPv4 datagram send accepted `MSG_OOB` silently; the reference refuses it before it looks at the destination. The IPv6 sender carries no such check, so an AF_INET6 socket reaches it only for a v4-mapped destination | guest `t_cmsgfam`: pre-branch `udp_oob rc=1`, oracle errno=95 | B1960 |
| FIXED 98baa58a3 | DEFECT | med | `NetError::Enodev` was mapped to ENXIO for every send, so an IPv6 send whose `IPV6_PKTINFO` named a missing interface reported ENXIO where the reference reports ENODEV, while AF_PACKET's genuine ENXIO was reachable only through that conflation | separate `NetError::Enxio` variant; `net::sock::packet_ring_tx_tests::destination_resolution_preserves_missing_foreign_down_and_short_address_errors`, positive control RED | B1960 |
| FIXED 98baa58a3 | DEFECT | low | AF_PACKET checked the interface state before the device-sized `sockaddr_ll` length, inverting the reference's order | same test, new down-plus-short case | B1960 |
| FIXED 98baa58a3 | DEFECT | low | AF_PACKET receive ignored flags it has no answer for; it is the one family that whitelists the whole flag word and reports EINVAL | `net::sock::packet_tests::a_packet_receive_accepts_exactly_the_flags_the_family_answers`, positive control RED | B1960 |
| FIXED 98baa58a3 | DEFECT | med | A TCP `MSG_OOB` send of more than one byte was refused with EINVAL; the reference sends every byte and marks the last urgent, and a zero-length one reports zero rather than refusing | `socket::oob::tests::a_tcp_send_marks_its_last_byte_and_reports_zero_for_an_empty_one`, positive control RED | B1960 |
| OPEN | MISSING | med | The per-message `SO_MARK`, `SO_PRIORITY`, `SCM_TXTIME` and `SO_TIMESTAMPING` values are admitted exactly as the reference admits them (capability, band and width), but nothing consumes them on transmit. The socket-level `SO_MARK` is in the same state: it is stored by the option table and never reaches the route lookup, which does take a mark (`route::lookup_result_mark_in` has no caller outside forwarding). One owner has to consume both, and that owner is the transmit path's mark plumbing, not the ancillary rule | `net::sock_opts::sol_socket::set` stores `Action::Mark`; `grep` for a reader on the socket TX path finds none | sock_opts / transmit lane |
| OPEN | DEFECT | low | An AF_UNIX SOCK_DGRAM **socketpair** (`UnixMsgPair` with datagram kind) ignores a supplied destination; the reference resolves it with the ordinary name lookup. The path-bound datagram socket does honour the name | `socket::control::prepare_unix` treats every `UnixMsgPair` as the stream kind for the name rule | B1960 lane, unclaimed |
| OPEN | COVERAGE | low | The guest differential probe `t_cmsgfam` covers the privilege-independent answers only. The capability-gated SOL_SOCKET types (`SO_MARK`, `SO_PRIORITY` above the interactive band) and the whole IPv6 ancillary level have hosted coverage but no differential frame, because the probe's uid is not pinned across host and guest | `tools/network-conformance-manifest.tsv` rows 44/46 record the gap in their closure contract | unclaimed |
| OPEN | INFRA | low | The SSH conformance transport still times out on this box (`oxide-conformance: SSH timeout`), so every guest differential here went through the serial transport. The serial path works on both arches | two consecutive `tools/oxide-conformance-ssh.sh x86_64 t_mmsg` runs reached a booted guest with `sshd` running and never completed the exec | N22 channel lane |

## Negative results worth keeping

- **AF_PACKET observation parity is NOT a gap.** Row 44 carried it as one. The
  outgoing tap, the `PACKET_OUTGOING` marking, the own-socket and fanout-group
  exclusions, `PACKET_IGNORE_OUTGOING`, the `sll_pkttype` classification,
  `PACKET_ORIGDEV`, the `PACKET_AUXDATA` record including its VLAN fields and
  the outgoing checksum-validity suppression, and the vnet header are all
  implemented and carry 96 hosted tests. The row text is corrected rather than
  worked.
- **`PACKET_LOOPBACK` (pkttype 5) has no constant in the tree.** It matters only
  for marking an IP multicast frame this host looped back to itself, which the
  receive path drops before delivery. Nothing else depends on it.
- **`SOCK_NOFCS` is stored by the option table and has no transmit consumer**, so
  an AF_PACKET send never reports EPROTONOSUPPORT for a device that cannot do
  it. Same shape as the `SO_MARK` row above.
