# B1761 — resolved address scope delivery

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1761 | DEFECT | high | `systemd-resolved` retained no DNS scope after the kernel delivered a link-up and DHCP IPv4 address notification. | Linux requires `NETLINK_PKTINFO` to carry each multicast group to `recvmsg`; systemd-resolved enables it and dispatches its route callbacks by that group. The queue had discarded the group and emitted no ancillary packet info. The x86 serial probe now shows `Current Scopes: DNS LLMNR/IPv4` and `Current DNS Server: 10.0.2.3` without restarting resolved. | B1761 |
