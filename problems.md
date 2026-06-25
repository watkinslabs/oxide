# Problems

- IPv4 primary-address state is split between SIOCSIFADDR and RTM_NEWADDR. `syscalls::siocgif` owns the source-address hook used by outbound sockets, while `netlink::rtnetlink` owns the address table reported by RTM_GETADDR. Unify these so ioctl and rtnetlink address mutation feed one live per-interface address owner.
