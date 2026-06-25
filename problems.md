# Problems

## Open

- IGMPv3/MLDv2 source-list query handling is not implemented. Report formats are wired, but inbound source-specific multicast listener queries still need parser/state handling.
- IPv6 addresses are not exposed through RTM_GETADDR. The IPv6 stack has SLAAC/manual address state, but rtnetlink currently only dumps AF_INET rows.

## Resolved

- IPv4 primary-address state was split between SIOCSIFADDR and RTM_NEWADDR. Fixed by moving primary IPv4 address ownership into `net::iface_addr`, with ioctl and rtnetlink both writing the same per-interface state.
