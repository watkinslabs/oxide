# Problems

## Open

- None currently recorded.

## Resolved

- IPv4 primary-address state was split between SIOCSIFADDR and RTM_NEWADDR. Fixed by moving primary IPv4 address ownership into `net::iface_addr`, with ioctl and rtnetlink both writing the same per-interface state.
