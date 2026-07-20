// Linux `struct arpreq` and SIOC*ARP command contract from uapi/linux/if_arp.h.

pub const SIOCDARP: u64 = 0x8953;
pub const SIOCGARP: u64 = 0x8954;
pub const SIOCSARP: u64 = 0x8955;

pub const AF_INET: u16 = 2;
pub const ARPREQ_SIZE: usize = 68;
pub const SOCKADDR_SIZE: usize = 16;
pub const ARPREQ_PA_OFFSET: usize = 0;
pub const ARPREQ_HA_OFFSET: usize = ARPREQ_PA_OFFSET + SOCKADDR_SIZE;
pub const ARPREQ_FLAGS_OFFSET: usize = ARPREQ_HA_OFFSET + SOCKADDR_SIZE;
pub const ARPREQ_NETMASK_OFFSET: usize = ARPREQ_FLAGS_OFFSET + core::mem::size_of::<i32>();
pub const ARPREQ_DEV_OFFSET: usize = ARPREQ_NETMASK_OFFSET + SOCKADDR_SIZE;
pub const IFNAMSIZ: usize = ARPREQ_SIZE - ARPREQ_DEV_OFFSET;
pub const SOCKADDR_DATA_OFFSET: usize = core::mem::size_of::<u16>();
pub const SOCKADDR_IN_ADDR_OFFSET: usize = core::mem::size_of::<u16>() * 2;
pub const ETHERNET_ADDRESS_BYTES: usize = 6;

pub const ATF_COM: u32 = 0x02;
pub const ATF_PERM: u32 = 0x04;
pub const ATF_PUBL: u32 = 0x08;
pub const ATF_USETRAILERS: u32 = 0x10;
pub const ATF_NETMASK: u32 = 0x20;
pub const ATF_DONTPUB: u32 = 0x40;
pub const ARPREQ_PROXY_FLAGS: u32 = ATF_PUBL | ATF_NETMASK | ATF_DONTPUB;
