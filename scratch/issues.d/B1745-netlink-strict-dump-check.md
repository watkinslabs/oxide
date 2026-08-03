# B1745 — strict dump validation

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1745 | DEFECT | med | `handle_getaddr_in` took no message body, so a `RTM_GETADDR` dump carrying an `ifa_index` filter was answered with every address in the namespace. `ip addr show dev eth0` received loopback's addresses alongside eth0's. | `crates/kernel/netlink/src/rtnetlink_tests/strict_dumps.rs` `a_strict_address_dump_answers_only_the_device_the_caller_named`; positive control: deleting the filter line turns it RED | — |
| FIXED B1745 | DEFECT | low | A `RTM_GETLINK` dump carrying a non-zero `ifi_index` was answered with every device. Link dumps define no device filter, so the reference refuses the request rather than silently ignoring the field. | `a_strict_link_dump_refuses_a_device_filter_it_cannot_honour` | — |
| FIXED B1745 | MISSING | low | Dump replies never carried `NLM_F_DUMP_FILTERED`, so a client could not tell a filtered answer from a full one. | the filtered-flag assertions in `strict_dumps.rs` | — |
| OPEN | COVERAGE | low | `getlink_one` and the dump builders return bare errno literals (`-22`, `-19`) rather than `Errno::Einval`/`Errno::Enodev`. New code in this lane uses the typed constants; the pre-existing sites were left alone to keep the diff to one change. | `crates/kernel/netlink/src/rtnetlink/dumps.rs` `getlink_one` | — |
| OPEN | MISSING | low | Strict validation does not yet reject unknown attributes in a dump request (`nlmsg_parse_deprecated_strict` against `ifa_ipv4_policy`/`ifla_policy`), nor honour `IFA_TARGET_NETNSID`/`IFLA_TARGET_NETNSID`. | `crates/kernel/netlink/src/rtnetlink/dump_req.rs` validates the family header only | — |
