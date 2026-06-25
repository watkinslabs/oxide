# Problems

## Open


## Resolved

- IPv4 primary-address state was split between SIOCSIFADDR and RTM_NEWADDR. Fixed by moving primary IPv4 address ownership into `net::iface_addr`, with ioctl and rtnetlink both writing the same per-interface state.
- IPv6 addresses were not exposed through RTM_GETADDR. Fixed by dumping the stack's configured IPv6 addresses as AF_INET6 RTM_NEWADDR rows.
- IPv6 RTM_GETADDR rows used permanent /128 lifetime metadata. Fixed by retaining IPv6 address prefix length plus SLAAC preferred/valid lifetimes and emitting them in AF_INET6 cacheinfo.
- IGMPv3/MLDv2 source-list query handling was missing. Fixed by parsing source lists from inbound source-specific queries and reflecting them in matching listener reports.
