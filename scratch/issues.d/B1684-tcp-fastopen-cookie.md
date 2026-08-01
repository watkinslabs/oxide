# B1684 — fast-open option codec (TFO ladder, stage 2)

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED B1684 | med | No fast-open option existed in the header codec at all: neither the assigned kind 34 nor the RFC 6994 experimental form (kind 254, experiment id `0xF989`). A peer offering either was invisible, and this side could not have answered one. | `tcp_hdr::opt` carried only MSS / WScale / SACK-permitted / SACK / Timestamp. Now `parse_fastopen_option` reads both forms and `SynOptions::fastopen` writes both, byte-pinned for every cookie length under both kinds. | B1684 |
| FIXED B1684 | med | `parse_wscale_option` clamped a peer's advertised window scale with a bare literal `14`, duplicating `sol_tcp::TCP_MAX_WSCALE`. Two copies of one RFC limit that could drift, and a magic number in a position `07§5` names explicitly. | Now one owner, `tcp_hdr::WSCALE_MAX`, which `TCP_MAX_WSCALE` aliases; `a_peer_scale_above_the_ceiling_is_clamped_on_the_wire` asserts both the clamp and that the two constants are the same value, and fails when the clamp is removed. | B1684 |
| RETRACTED B1684 | — | **This lane's own B1673 row claiming `rcv_wscale` takes a peer's scale verbatim with no ceiling was WRONG.** `parse_wscale_option` already clamped; the audit that reported otherwise did not read the parser body, and I filed the row without checking. Caught by a positive control: a clamp test written against the wrong site passed with the clamp neutered. The real defect was the duplicated literal above, which is a different and smaller problem. | Fold instruction: the `TCP_MAX_WSCALE` row in the B1673 drop must NOT be carried into the curated ledger — it describes a defect that never existed. | B1684 |
| OPEN | med | The fast-open codec has no production caller yet: `TcpConn::syn_options` sets `fastopen: None`. The cookie's key owner (listener accept-queue and namespace) and the mint/verify that fills it in are the next change in this ladder, so the caller arrives in the immediately-following PR rather than at some unnamed later date. Recorded so that if the ladder stalls, the dead codec is visible rather than assumed live. | `segment.rs syn_options`. Codec fully exercised by `tcp_conn::fastopen::tests` and `syn_opts::tests` (23 tests). | B1684 |
| OPEN | med | Two hand-rolled option writers remain (`sack.rs` build_ack_with_sack, `segment.rs` build_segment_at), carried over from the B1673 drop. Neither is a live defect; both should fold into a non-SYN option assembler rather than a third and fourth writer being added beside them. | Carried forward from B1673. | — |

## Curated rows to fold

- The B1673 drop's `TCP_MAX_WSCALE` row is **retracted** — see the RETRACTED row above. Drop it rather than folding it.
- The curated fast-open row (`Fast-open family … stored with nothing consuming it`) still stays as written: `TCP_FASTOPEN`, `_KEY` and `_CONNECT` remain stored with no consumer, and `TCP_FASTOPEN_CONNECT -> EOPNOTSUPP` is still correct for a zero enable bit. It gets rewritten by the stage that lands the sysctl.

## Scope note

The ownership move (`fastopen_max_qlen` and the key from the per-socket option
block to the listener accept-queue and the namespace) was scoped into this stage
but is deferred to the next one, deliberately: moving the key without the
mint/verify that consumes it only relocates dead state, and it is the one part
that must edit the gated `sock_opts::sol_tcp` module that is currently red on
main from B1660. The key lands together with its consumer.
