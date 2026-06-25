# Problems

## Open

- IGMPv3/MLDv2 source-list query handling is not implemented. Report formats are wired, but inbound source-specific multicast listener queries still need parser/state handling.
- IPv6 RTM_GETADDR rows use permanent /128 lifetime metadata. The IPv6 stack does not yet retain SLAAC prefix preferred/valid lifetimes after applying Router Advertisements.

## Resolved

- IPv4 primary-address state was split between SIOCSIFADDR and RTM_NEWADDR. Fixed by moving primary IPv4 address ownership into `net::iface_addr`, with ioctl and rtnetlink both writing the same per-interface state.
- IPv6 addresses were not exposed through RTM_GETADDR. Fixed by dumping the stack's configured IPv6 addresses as AF_INET6 RTM_NEWADDR rows.
