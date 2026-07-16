// Linux `IFF_*` interface flags shared by control and data planes.

pub const IFF_UP:        u32 = 0x0001;
pub const IFF_BROADCAST: u32 = 0x0002;
pub const IFF_LOOPBACK:  u32 = 0x0008;
pub const IFF_RUNNING:   u32 = 0x0040;
pub const IFF_PROMISC:   u32 = 0x0100;
pub const IFF_ALLMULTI:  u32 = 0x0200;
pub const IFF_MULTICAST: u32 = 0x1000;
