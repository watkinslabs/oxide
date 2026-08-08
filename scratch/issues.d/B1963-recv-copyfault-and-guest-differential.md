# B1963 — receive copy-fault transactions + guest differential over real uaccess

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED | DEFECT | HIGH | An AF_UNIX / TCP / VSOCK stream receive whose destination faulted PARTWAY through one queued fragment reported the landed prefix as delivered and retired those bytes. A stream consumes queued fragments WHOLE: a fragment whose copy faults is consumed by nothing, ends the receive, and the call answers with what earlier fragments delivered — or EFAULT when none did. Reporting the prefix retires bytes the transport still holds, so the caller is told it received data it can never read. | Guest differential `t_recvfault`: against the pre-branch kernel `stream_payload_split` returns `rc=1024` where the oracle returns `rc=-1 errno=14` — the ONLY diverging line of 22, and the proof the channel can fail. Hosted: `syscalls::recv_user::tests::a_stream_fragment_is_all_or_nothing_only_when_the_destination_faults`. Positive control: restoring the byte-granular `copy_payload_at` in the fragment path reddens it. | B1963 |
| FIXED | DEFECT | MED | A control-stream copyout that faulted mid-stream discarded the ENTIRE cursor, publishing `msg_controllen = 0` for a buffer that already held one or more complete control messages. Every ancillary entry that landed keeps the space it took; the faulting entry and everything after it contribute nothing. | `syscalls::recv_control::tests::a_faulting_control_entry_keeps_the_prefix_that_landed` (three fault positions, driven through the real cursor with a scripted byte move). Guest differential `dgram_control_split rc=8 controllen=32` with the second cmsg starting on an unmapped page. Positive control: returning `copied: 0` on the fault reddens it. | B1963 |
| FIXED | DEFECT | MED | The error-queue receive and the TCP receive published the source ADDRESS before the control stream; every other family published control first. Order matters when one of them faults: a name fault must leave the control bytes already written. The publication order (payload, control, name, `msg_flags`, `msg_controllen`) now has ONE owner, `syscalls::recv_txn`, used by AF_INET/AF_INET6 datagram, raw, packet, TCP, TCP out-of-band, the error queue, AF_UNIX (all four flavours), NETLINK, VSOCK stream, VSOCK seqpacket and the VSOCK error queue. | `syscalls::recv_txn::tests` (9), notably `an_unwritable_name_fails_the_receive_before_either_header_word`, which asserts the control stream landed first. Positive control: swapping the two steps in `publish` turns two tests red. | B1963 |
| FIXED | MISSING | MED | `IPV6_RECVPATHMTU` was stored by the option table and readable by `getsockopt`, and nothing ever consumed it — a socket that switched it on could never receive a path-MTU announcement. It is a SECOND mechanism beside the extended-error queue, with its own one-slot storage, its own replacement rule and its own consumption point: an ORDINARY receive answers with it ahead of anything queued. Now generated from the one host-detected-size-failure owner and consumed by the one receive publication. | `net::socket_error::pathmtu::tests` (3); `net::socket_error::tests::origins::the_path_mtu_announcement_is_stashed_only_when_the_socket_asked_for_it`, which also pins that reading the announcement leaves the queue record alone. Positive control: dropping the `recvpathmtu` guard reddens it. | B1963 |
| FIXED | COVERAGE | HIGH | The `MSG_ERRQUEUE` / receive copyout paths are target-gated, so no check anywhere could fail if a copy-fault rule broke. Rows 47 and 299 both named this as their last open item. `userspace/glibc_conformance/t_recvfault.c` now drives 22 differential lines through the real syscall entry over real user memory — unmapped pages, and pages mapped up to a `PROT_NONE` boundary so a copy faults PARTWAY. | `tools/oxide-conformance-serial.sh {x86_64,aarch64} t_recvfault 180` — PASS on both arches, 22/22 lines matching the live host oracle. Manifest rows 47 and 299. | B1963 |
| FIXED | COVERAGE | MED | Every probe-gated `make smoke-*` target overrode `SMOKE_MARKER` but left `boot-smoke.sh`'s debug-shell liveness fallback on, so the boot could be declared alive — and the target green — before the unit that runs the probe had executed. This is the filed reason a prior lane's unmapped-pointer EFAULT assertion never ran (`B1945`). All six such targets now pass `SMOKE_ALIVE_PROBE=`, forcing the passive marker grep, which by construction cannot fire until the probe has printed its verdict. | `Makefile` `smoke-{request-key,swapfile,gnome-input-classify}-{x86,arm}`; `boot-smoke.sh:101` `ALIVE_PROBE="${SMOKE_ALIVE_PROBE-1}"`. | B1963 |

## Negative results worth keeping

- **VSOCK send-side address/control parity is NOT open.** Row 47 still listed it.
  B1960 closed it and it verifies: `socket::vsock_addr::established` judges a
  destination by connection STATE (`VsockState::Connected | RcvShutdown`), not by the
  socket variant; `admit_datagram` shape-checks an unbound cast address with EINVAL
  rather than refusing it with EOPNOTSUPP; and `socket::send::prepare`'s vsock arm
  consults NO ancillary rule. Both tests are in an ungated module and run
  (`cargo test -p socket vsock_addr`, 2 passed). The row text is corrected rather
  than worked.
- **Protocol-specific IP ancillary RECEIVE coverage was one option short, not
  absent.** `net::cmsg::plan` already generates and the real `recvmsg` path already
  emits IP_PKTINFO, IP_TTL, IP_TOS, IP_RECVOPTS, IP_RETOPTS, IP_PASSSEC,
  IP_ORIGDSTADDR, IP_CHECKSUM, IP_RECVFRAGSIZE, the whole RFC3542 IPv6 set
  (PKTINFO, HOPLIMIT, TCLASS, FLOWINFO, HOPOPTS, DSTOPTS, RTHDR, ORIGDSTADDR,
  RECVFRAGSIZE), the RFC2292 legacy twins and UDP_GRO, in Linux's frequency order,
  with 28 hosted tests. `IPV6_RECVPATHMTU` was the single gap and is the row above.
- **An AF_UNIX stream is fragment-granular, not byte-granular, and that is not a
  TCP difference.** Both stream transports consume the fragment they copied, and
  neither consumes one it could not copy whole. The 4096-byte case in the probe is
  one fragment, which is why the reference answers EFAULT rather than 1024.
- **An unwritable `msghdr` does not consume a datagram.** The header is imported
  before the receive runs, so the call fails before any transport is asked.
  `dgram_hdr_dead_left rc=8` on both the oracle and the guest.
- **An unwritable ancillary buffer does not fail a receive.** The call still
  returns its byte count, its address and its flags, with a zero control length.
  This was already correct here and is now pinned by the probe on both arches.

## Open

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | MISSING | LOW | `IPV6_PATHMTU` as a `getsockopt` — the current route MTU, ENOTCONN when there is none — is not implemented. It is a different question from the `IPV6_RECVPATHMTU` announcement this branch closed, and it lives in `net/src/sock_opts/sol_ipv6`, owned by another lane. | `grep IPV6_PATHMTU crates/kernel/net/src/sock_opts/` finds no `get` arm. | sock_opts lane |
| OPEN | COVERAGE | LOW | The differential probe covers IPv4 UDP, AF_UNIX stream and the `recvmmsg` batch. VSOCK and NETLINK receive copy-faults have hosted coverage of the shared publication but no differential frame, because neither family has a host-side oracle reachable from an unprivileged probe. | `tools/network-conformance-manifest.tsv` rows 47/299 record the gap in their closure contract. | unclaimed |
