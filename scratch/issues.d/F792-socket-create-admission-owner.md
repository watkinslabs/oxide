# F792 — socket(2) creation admission owner

Lane: `F792-socket-create-admission-owner`. Scope: the `NEEDS-REWORK` socket rows
of `scratch/syscall-compliance-matrix.md` (41, 50, 54, 55, 288).

## Fixed

| Item | Evidence |
|---|---|
| The `socket(2)` admission sequence lived entirely in `crates/kernel/syscalls/src/041_socket.rs`, which is `#![cfg(target_os = "oxide-kernel")]`. Every ordering decision B1641 had just corrected — creation hook above protocol resolution and above the CAP_NET_RAW screen — was therefore unverifiable: a `#[cfg(test)]` block there compiles out silently. Moved to the ungated `net::socket_create::plan`. | `cargo test -p net --lib -- --test-threads=1` 1713 passed / 0 failed, up from 1703; 10 new `socket_create::tests` cases. |
| The gate can observe its own failure mode: moving the decision back below `resolve_socket_args` fails `the_creation_decision_outranks_protocol_support_and_the_raw_capability` and `the_hook_observes_the_renamed_family_the_masked_type_and_the_raw_protocol`. | Perturbation run, 9 passed / 2 failed. |
| A denied creation returned EPERM while every other denied network operation returns EACCES — a split answer for one policy boundary. Creation now answers EACCES, which is also what the labelling modules that implement this hook return from it. | `socket_create::CREATE_DENIED`, asserted by every denial case. |
| `docs/53` layering: the slot held identity parsing, the security decision, resolution, the two VSOCK transport screens and the ICMP group admission. It now builds a `CreateEnv`, calls one work-fn, and installs the descriptor. | `crates/kernel/syscalls/src/041_socket.rs` −34 lines. |

## Open

| Item | Why not closed here |
|---|---|
| Rows 50 (`listen`) and 288 (`accept4`) stay `NEEDS-REWORK`. TCP_DEFER_ACCEPT completes the handshake and withholds the child from `accept`; Linux drops the bare ACK and leaves the peer retransmitting. | Unimplemented behaviour, not missing evidence. Needs a request-sock minisock, which is its own lane. |
| Rows 54 (`setsockopt`) and 55 (`getsockopt`) stay `NEEDS-REWORK`: TCP_ZEROCOPY_RECEIVE returns ENOPROTOOPT, fast-open is stored but never consumed, IP_OPTIONS and the IPv6 sticky headers are never emitted on transmit, IP_CHECKSUM is inert, and the IP/IPV6/PACKET option families are unaudited. | Same reason: behaviour gaps, and each family is a lane's worth of work. |
| Object construction for row 41 — the family-to-inode match, netlink listener registration, dentry/File creation — is still in the slot file. | It reaches `netlink` and `vfs` types the `net` crate does not own; splitting it is a separate refactor. The decision, which is where the ordering bugs were, is now out. |
| No glibc differential for `socket(2)`. | Verification for this lane is hosted-only by instruction; the row was promoted on hosted ordering, permission, namespace and ownership evidence, with no user-copy case to cover because the syscall takes no user pointer. |
