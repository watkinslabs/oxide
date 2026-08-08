# B1961 — setsockopt/getsockopt option matrix, LSM surface, teardown, glibc differential

Rows 54/55 of `scratch/syscall-compliance-matrix.md`. Every claim below was
re-checked against current code and against the reference before it was written
down; the stale ones are recorded as stale, because retracting them is worth as
much as a fix.

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED 522e6361 | DEFECT | med | The socket-option security decision named neither the option nor the direction: one `Operation::Option` for reads and writes alike, carrying no level, no option number and a zeroed socket type/protocol. A module could permit or refuse the whole interface and nothing finer, and could not publish state while refusing changes to it. | `net::socket_security::option` now owns both decisions; `socket_security::option::tests` 6 tests, positive control: routing `setsockopt` to the read operation fails 4 of them | B1961 |
| FIXED 522e6361 | DEFECT | med | A negative `optlen` was screened AFTER the security hook on three of the four `setsockopt` routes (generic inet, netlink SOL_SOCKET, vsock), where the reference screens it first. A module was consulted about, and could allow, a malformed write. | `net_common::tests` scoped per-route source-order assertion; positive control: reinstating the old order on the inet route fails it (the earlier whole-file check did NOT catch it — the filter route's own screen stood in for the others) | B1961 |
| FIXED 0012a45d | DEFECT | low | `PACKET_FANOUT_DATA` checked the filter lock before the fanout group, so a socket that was filter-locked and in no group (or in a group whose selector is not a program) reported EPERM where the reference reports EINVAL. Both the shim and the apply had the inversion. | `packet_optshape::tests::a_fanout_data_write_is_judged_by_its_group_before_its_filter_lock`; positive control RED then GREEN | B1961 |
| FIXED eaea52b1 | DEFECT | low | `IPV6_PKTINFO` answered a getsockopt read. The reference's read table has no arm for it — it is a write and an ancillary type, and the value comes back through the receive control message. | `sol_ipv6::tests::reads::the_sticky_source_option_has_no_readback`; the sticky value keeps its transmit consumer | B1961 |
| FIXED 02b6121e | DEFECT | high | SOL_SOCKET on a netlink fd was answered by a second, three-option table. Every other option number was accepted and silently discarded (a client setting its buffer sizes was told the write took effect), the receive timeout had its own arithmetic with no `EDOM` screen and no negative-seconds rule, reads refused a short buffer instead of truncating, and the socket identity was a second copy. | `socket_control_tests::netlink_sol_socket_defers_to_the_one_generic_table`; positive control: reintroducing the duplicate arithmetic constant fails it | B1961 |
| FIXED 02b6121e | DEFECT | low | `NETLINK_LIST_MEMBERSHIPS` copied whole BYTES where the reference copies whole WORDS: a capacity that stopped mid-word delivered half a word. | `netlink_getsockopt_policy::tests::a_word_granular_read_delivers_only_whole_words` | B1961 |
| FIXED dffa48dd | DEFECT | med | `IPV6_AUTOFLOWLABEL` had two answers. The read resolved an un-named socket against a namespace default the shim hardcoded to `false` (the reference default opts sockets IN, so an untouched socket read back 0 instead of 1); the transmit paths skipped the resolution entirely and read the raw socket bit, so neither could see the namespace policy nor its two overrides (forbid for every socket / force on one that opted out). | `sol_ipv6::autolabel::tests` 3 tests + the read test; positive control: flipping the default policy set fails 2 | B1961 |
| FIXED 8d70616b | DEFECT | med | A multicast source-filter write faced NO memory ceiling: neither the option-memory limit on the whole request nor the family's source-count maximum, and the count whose byte size overflows 32 bits was unscreened. All three are ENOBUFS in the reference and all precede the length-versus-count EINVAL. | `sock_opts::msfilter::tests` 5 tests; positive control: deleting the count ceiling fails 2. New leaves `net.ipv4.igmp_max_msf` (per-namespace, 10) and `net.ipv6.mld_max_msf` (global, 64) | B1961 |
| FIXED 5a920c9a | DEFECT | med | `IPV6_DONTFRAG` reached the transmit decision only as a per-message control. A socket that set the sticky option was stored and read back correctly while its packets fragmented anyway. | `send_control::tests::a_sticky_fragmentation_refusal_reaches_the_same_slot_as_a_per_message_one`; positive control RED then GREEN | B1961 |
| OPEN | MISSING | med | A netlink socket has no home for most generic SOL_SOCKET state. `SO_PRIORITY`, `SO_MARK`, `SO_LINGER`, the timestamp personalities, `SO_BINDTODEVICE` and the rest are now VALIDATED by the canonical ladder but land in the generic flag/scalar word with no family behaviour behind them, and `SO_SNDTIMEO` has no wait to bound. The Linux shape is one `struct sock` base shared by every family; this tree has `InetSocket.opts` and a partial copy on `NetlinkSocket`. | `crates/kernel/syscalls/src/netlink_fd/sol_socket.rs` `apply`'s final arm; `crates/kernel/netlink/src/netlink_socket.rs:45` | — |
| OPEN | MISSING | low | `UDP_ENCAP` accepts the reference's value set and is stored, with zero consumers: there is no ESP-in-UDP or L2TP decapsulation path in the tree at all, so the option selects nothing. | `net::sock_opts::sol_udp::table` `encap_type`, no reader outside `sol_udp` | — |
| OPEN | MISSING | low | `IPV6_RECVPATHMTU` stores and reads back its bit with no consumer: no receive path emits the `IPV6_PATHMTU` ancillary message the bit asks for. | `sol_ipv6/set.rs:199` writes `flag::RXPATHMTU`, `get.rs:96` reads it, no other reader in the tree | — |
| OPEN | DEFECT | low | `IPV6_2292PKTOPTIONS` is a stream-socket ancillary snapshot in the reference; ours answers zero bytes on read and accepts only `optlen == 0` on write. | `sol_ipv6/get.rs` `IPV6_2292PKTOPTIONS` arm returns an empty `Vec`; `054_setsockopt/ipv6.rs` | — |
| OPEN | DEFECT | low | `TCP_INFO`'s published struct ends at the retransmit-time field and omits the AccECN tail the reference's uapi now carries, so a caller reading the current structure size gets a short answer. | `crates/kernel/syscalls/src/tcp_info.rs` | — |
| OPEN | DEFECT | low | `SO_ERROR` reports only the primary error; the reference falls back to the soft (ICMP-derived, non-fatal) error when the primary is clear, reporting it once. | `crates/kernel/syscalls/src/recvmsg/dispatch.rs` `take_error()` has no soft slot. Overlaps B1959's error-queue ownership — not touched here | B1959 |
| OPEN | COVERAGE | med | No differential probe corpus exercises `setsockopt`/`getsockopt` at SOL_NETLINK or SOL_SOCKET-on-netlink. `userspace/af_packet_diff/` covers SOL_PACKET and `userspace/glibc_conformance/t_{set,get}sockopt.c` covers neither level; the netlink defects fixed here were found by reading, not by a run. | `grep -n "NETLINK" userspace/glibc_conformance/t_setsockopt.c` is empty | — |

## Retracted claims — checked and found NOT to be defects

- **IPv6 sticky extension headers are consumed.** `Raw6Control::merge_sticky_headers`
  is called from the raw6, UDP6 and TCP transmit paths. An audit pass reported
  them stored-only on the grounds that `Ipv6Opts::header_chain` has only test
  callers; the merge reads the slots directly and `header_chain` is a different
  interface. B1939's retraction stands.
- **`IP_PROTOCOL` has no set arm in the reference.** Confirmed again: refusing
  the write is correct, not an omission.
- **Device removal and namespace teardown of option state match.** Audited
  option by option for every option that references a device or a
  namespace-scoped object. Device-side multicast/anycast aggregate state is
  released on unregister and per-socket join records deliberately survive until
  close — the same split the reference keeps. AF_PACKET binds and memberships
  are the one class actively torn down with ENETDOWN, and both trees do it.
  Raw ifindex options (`SO_BINDTODEVICE`, `IP_MULTICAST_IF`, the unicast pair)
  are resolved lazily in both trees, so a dangling index is by design.
  Namespace teardown releases routes, rules, reassembly, the packet table, mib
  counters, bind tables and port reservations, the security hooks and the
  registry entry; a live socket pins its namespace, so teardown cannot race one.
  **No work is owed here** — this part of rows 54/55 is closed.
- **The glibc differential has no marshalling divergence on either target.**
  Both are LP64: the wrappers are direct syscalls with no option-number
  aliasing, no struct translation and no errno remapping. The `_OLD`/`_NEW`
  time64 split is a 32-bit concern and both targets take the `_OLD` numbers,
  which is what our table implements. The gap here is coverage, filed above,
  not behaviour.
