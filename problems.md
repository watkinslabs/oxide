# Problems

## Open

- IPv4 forwarding drops transit packets with expired TTL or missing routes silently instead of generating ICMP Time Exceeded / Destination Unreachable. Track as a forwarding refinement after basic router mode.

## Resolved

- IPv4 primary-address state was split between SIOCSIFADDR and RTM_NEWADDR. Fixed by moving primary IPv4 address ownership into `net::iface_addr`, with ioctl and rtnetlink both writing the same per-interface state.
- IPv6 addresses were not exposed through RTM_GETADDR. Fixed by dumping the stack's configured IPv6 addresses as AF_INET6 RTM_NEWADDR rows.
- IPv6 RTM_GETADDR rows used permanent /128 lifetime metadata. Fixed by retaining IPv6 address prefix length plus SLAAC preferred/valid lifetimes and emitting them in AF_INET6 cacheinfo.
- IGMPv3/MLDv2 source-list query handling was missing. Fixed by parsing source lists from inbound source-specific queries and reflecting them in matching listener reports.
- Policy routing rules were not enforced by the live IPv4 data path. Fixed by moving custom rules into the net layer, making IPv4 routes table-aware, and selecting routes by effective rule priority.
- Legacy SIOCADDRT route insertion was not table-aware after route entries gained table selection. Fixed by inserting ioctl-created routes into the main routing table.
- `/proc/sys/net/ipv4/ip_forward` was registered twice, with a later read-only static file shadowing the writable sysctl. Fixed by using one inode backed by live IPv4 forwarding state.
- IPv4 route lookup ignored ECMP and always selected the first equal-prefix route. Fixed by selecting among equal-cost routes with a stable destination hash.
- RTM_NEWROUTE ignored RTA_MULTIPATH nexthop arrays. Fixed by parsing multipath nexthops and inserting each as an equal-cost IPv4 route row.
- RTM_GETROUTE did not emit RTA_MULTIPATH for ECMP route dumps. Fixed by grouping equal-cost IPv4 route rows and exporting them as multipath nexthops.
