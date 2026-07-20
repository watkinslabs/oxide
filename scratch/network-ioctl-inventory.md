# Network ioctl inventory

Status: IN-PROGRESS. Branch: D352-network-ioctl-inventory. Linux UAPI source:
`linux/sockios.h` plus `asm-generic/sockios.h`; implementation audit source:
`crates/kernel/syscalls/src/016_ioctl/` and `siocgif.rs`.

| Commands | Linux owner | Oxide owner / status | Evidence | Closure test |
|---|---|---|---|---|
| `FIOSETOWN` (0x8901), `SIOCSPGRP` (0x8902), `FIOGETOWN` (0x8903), `SIOCGPGRP` (0x8904) | `sock_ioctl` async owner / fasync | Socket route implemented through canonical `File::f_setown`/`f_getown`; fasync SIGIO owner state is shared with `fcntl`; retained-namespace/family `Ioctl` admission precedes alias usercopy and f_owner access | `016_ioctl/common.rs`, `016_ioctl/core.rs`, hosted shape test, retained x86 `t_sockioctl` owner-alias match | real socket owner/process-group, SIGIO delivery, 32-bit compat |
| `SIOCATMARK` (0x8905) | socket urgent-data state | Implemented dispatcher; protocol result partial | `016_ioctl/common.rs`, `file_ops.rs` | TCP OOB mark before/at/after, non-TCP errno, target differential |
| `SIOCGSTAMP_OLD` (0x8906), `SIOCGSTAMPNS_OLD` (0x8907), `SIOCGSTAMP_NEW`, `SIOCGSTAMPNS_NEW` | socket receive timestamp | Missing | no route or timestamp copyout | AF_INET/AF_UNIX datagram, empty queue, timeval/timespec native+compat copyout |
| `SIOCINQ`/`FIONREAD`, `SIOCOUTQ`/`TIOCOUTQ`, `SIOCOUTQNSD` (0x894b) | socket queue accounting | `SIOCINQ`/`SIOCOUTQ` implemented; current tree implements TCP-only `SIOCOUTQNSD` from the unsent send buffer | `016_ioctl/common.rs`, `net/sock/io.rs`; retained x86 `t_sockioctl` host/guest match for TCP init, UDP rejection, listener rejection, and corked pending bytes | stream/datagram/seqpacket queue semantics, pending vs transmitted TCP bytes, faults |
| `SIOCADDRT` (0x890b), `SIOCDELRT` (0x890c), `SIOCRTMSG` (0x890d) | routing | add/delete implemented; `SIOCRTMSG` unused on Linux and absent | `siocgif.rs`, `route_ioctl` | capability, malformed route, namespace, IPv4/IPv6 route mutation and errno order |
| `SIOCGIFNAME` (0x8910), `SIOCGIFCONF` (0x8912), `SIOCGIFFLAGS` (0x8913), `SIOCGIFADDR` (0x8915), `SIOCGIFBRDADDR` (0x8919), `SIOCGIFNETMASK` (0x891b), `SIOCGIFMETRIC` (0x891d), `SIOCGIFMTU` (0x8921), `SIOCGIFHWADDR` (0x8927), `SIOCGIFINDEX` (0x8933), `SIOCGIFPFLAGS` (0x8935), `SIOCGIFCOUNT` (0x8938), `SIOCGIFTXQLEN` (0x8942), `SIOCGIFMAP` (0x8970) | netdevice / rtnetlink legacy ioctl | Implemented for current netdev model | `siocgif.rs`, `siocgif/tests.rs` | every getter: invalid pointer/name/index, namespace isolation, native/compat `ifreq` output and target frame |
| `SIOCSIFLINK` (0x8911), `SIOCSIFFLAGS` (0x8914), `SIOCSIFADDR` (0x8916), `SIOCSIFBRDADDR` (0x891a), `SIOCSIFNETMASK` (0x891c), `SIOCSIFMETRIC` (0x891e), `SIOCSIFMTU` (0x8922), `SIOCSIFNAME` (0x8923), `SIOCSIFHWADDR` (0x8924), `SIOCSIFPFLAGS` (0x8934), `SIOCSIFTXQLEN` (0x8943) | netdevice mutation | All except `SIOCSIFLINK` implemented; mutation security remains partial | `siocgif.rs`, `sioc_access` | capability-before-copy order, atomic state change, collision/range errno, concurrent reader and target differential |
| `SIOCGIFDSTADDR` (0x8917), `SIOCSIFDSTADDR` (0x8918), `SIOCGIFMEM` (0x891f), `SIOCSIFMEM` (0x8920), `SIOCGIFENCAP` (0x8925), `SIOCSIFENCAP` (0x8926), `SIOCGIFSLAVE` (0x8929), `SIOCSIFSLAVE` (0x8930), `SIOCADDMULTI` (0x8931), `SIOCDELMULTI` (0x8932), `SIOCDIFADDR` (0x8936), `SIOCSIFHWBROADCAST` (0x8937) | netdevice / family-specific legacy ioctl | Missing | no command route | family/device applicability, capability, multicast/address lifetime, native+compat `ifreq` differential |
| `SIOCGIFBR` (0x8940), `SIOCSIFBR` (0x8941) | bridge | Missing | no bridge owner | bridge option ABI, capability, port lifecycle, namespace isolation |
| `SIOCETHTOOL` (0x8946), `SIOCGMIIPHY` (0x8947), `SIOCGMIIREG` (0x8948), `SIOCSMIIREG` (0x8949), `SIOCWANDEV` (0x894a) | device driver | Missing | no driver ioctl boundary | driver-specific ABI, capability, ethtool command matrix, compat pointers |
| `SIOCGSKNS` (0x894c) | `sock_ioctl` namespace fd | Implemented | `016_ioctl/netns.rs`; B849 tests | any socket family, fd/CLOEXEC publication, permissions and fd-limit ordering |
| `SIOCDARP` (0x8953), `SIOCGARP` (0x8954), `SIOCSARP` (0x8955) | ARP / neighbour | Missing | no neighbour ioctl route | neighbour lookup/mutation, capability, address family, namespace, error order |
| `SIOCDRARP` (0x8960), `SIOCGRARP` (0x8961), `SIOCSRARP` (0x8962) | RARP legacy | Missing | no route | Linux availability/errno classification and capability tests |
| `SIOCGIFVLAN` (0x8982), `SIOCSIFVLAN` (0x8983) | VLAN | Missing | no VLAN owner | VLAN command union, capability, parent-device and namespace lifecycle |
| `SIOCADDDLCI` (0x8980), `SIOCDELDLCI` (0x8981) | Frame Relay DLCI | Missing | no DLCI owner | Linux availability/errno classification; device lifecycle if supported |
| `SIOCBONDENSLAVE` (0x8990), `SIOCBONDRELEASE` (0x8991), `SIOCBONDSETHWADDR` (0x8992), `SIOCBONDSLAVEINFOQUERY` (0x8993), `SIOCBONDINFOQUERY` (0x8994), `SIOCBONDCHANGEACTIVE` (0x8995) | bonding | Missing | no bonding owner | bond/slave lifecycle, capability, `ifreq` pointer ABI, namespace |
| `SIOCBRADDBR` (0x89a0), `SIOCBRDELBR` (0x89a1), `SIOCBRADDIF` (0x89a2), `SIOCBRDELIF` (0x89a3) | bridge lifecycle | Missing | no bridge owner | bridge lifecycle, capability, interface ownership and rollback |
| `SIOCSHWTSTAMP` (0x89b0), `SIOCGHWTSTAMP` (0x89b1) | NIC hardware timestamp | Missing | no timestamp-driver owner | config pointer ABI, driver capability, get/set round trip, compat |
| `SIOCPROTOPRIVATE` through `SIOCPROTOPRIVATE+15` (0x89e0–0x89ef) | protocol-specific `ioctl` | Missing generic registry by design | no protocol ioctl owner inventory | enumerate each supported protocol owner; unknown command must preserve Linux errno |
| `SIOCDEVPRIVATE` through `SIOCDEVPRIVATE+15` (0x89f0–0x89ff) | netdevice `ndo_do_ioctl` | Missing generic registry by design | no device ioctl owner inventory | enumerate per implemented driver; unsupported device/private command errno and compat |

## Required follow-up

1. Split `siocgif.rs` ownership into interface, route, and device ioctl work
   functions before adding commands; syscall slot 16 remains ABI dispatch only.
2. Add one machine-readable command-to-owner matrix before implementation so
   protocol/device-private ranges cannot acquire shadow dispatch.
3. Add native and compat Linux/Oxide conformance probes for every implemented
   command before promoting N24. Missing families remain explicit work, not
   `ENOSYS` substitutes.
