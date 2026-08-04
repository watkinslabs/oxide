# B1757 — an unqualified constant in a match arm

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1757 | DEFECT | med | The ICMP echo-reply arm named `ICMP_TYPE_ECHO_REPLY` unqualified, and that name is not in scope there. An unqualified name in a pattern position is a **binding**, not a comparison: it matched every ICMP type, counted every message as an echo reply, and made the following arm unreachable. Shipped in B1756 and caught by the compiler's warnings on `main`, not by any test. | `crates/kernel/net/src/tests_inet_netns.rs` `each_icmp_type_counts_in_its_own_column`; positive control — restoring the unqualified name fails it | — |
| OPEN | COVERAGE | med | Nothing fails a build on new warnings, so a warning that names a real defect can be merged. `cargo check` emitted three for this one — unreachable pattern, unused variable, non-snake-case binding — and every gate stayed green. A warnings ratchet like the spec-lint one would have stopped it. | `make feature-gate`/`hosted-gate` pass with warnings present | — |
