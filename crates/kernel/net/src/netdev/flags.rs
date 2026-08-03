// Linux `IFF_*` interface flags shared by control and data planes.

pub const IFF_UP:        u32 = 0x0001;
pub const IFF_BROADCAST: u32 = 0x0002;
pub const IFF_DEBUG:     u32 = 0x0004;
pub const IFF_LOOPBACK:  u32 = 0x0008;
pub const IFF_POINTOPOINT:u32 = 0x0010;
pub const IFF_NOTRAILERS: u32 = 0x0020;
pub const IFF_RUNNING:   u32 = 0x0040;
pub const IFF_NOARP:     u32 = 0x0080;
pub const IFF_PROMISC:   u32 = 0x0100;
pub const IFF_ALLMULTI:  u32 = 0x0200;
pub const IFF_MULTICAST: u32 = 0x1000;
/// Physical link is up. The reference does not STORE this: `dev_get_flags`
/// derives it at read time from the driver's carrier, alongside `IFF_RUNNING`
/// from the operational state, and only while the device is running.
pub const IFF_LOWER_UP:  u32 = 0x1_0000;
pub const IFF_DORMANT:   u32 = 0x2_0000;
pub const IFF_ECHO:      u32 = 0x4_0000;
pub const IFF_MASTER:    u32 = 0x0400;
pub const IFF_SLAVE:     u32 = 0x0800;

/// Flags userspace may never write: they describe what the device IS and what
/// its driver reports, not what an administrator asked for.
///
/// The reference keeps carrier out of `dev->flags` entirely — it lives in
/// `dev->state` — and `__dev_change_flags` takes only
/// `{DEBUG, NOTRAILERS, NOARP, DYNAMIC, MULTICAST, PORTSEL, AUTOMEDIA}` from
/// the caller, preserving `IFF_UP | IFF_VOLATILE | IFF_PROMISC | IFF_ALLMULTI`
/// from the device. Storing carrier in the same word a `SIOCSIFFLAGS` /
/// `RTM_SETLINK` writes let an ordinary "bring this link up" clear it, so the
/// link reported no carrier the moment anyone administered it — and a network
/// manager that has just brought a device up and is told it has no carrier
/// parks it at "unavailable" and never runs DHCP.
pub const IFF_VOLATILE: u32 = IFF_LOOPBACK | IFF_POINTOPOINT | IFF_BROADCAST
    | IFF_ECHO | IFF_MASTER | IFF_SLAVE | IFF_RUNNING | IFF_LOWER_UP | IFF_DORMANT;

/// The flags a device REPORTS, from the flags it stores plus its driver's
/// carrier — the reference's `dev_get_flags`.
///
/// `IFF_RUNNING` and `IFF_LOWER_UP` are never stored. They are computed here,
/// and only while the device is administratively up, because they answer "is
/// this link carrying traffic right now", not "what was it configured to do".
/// Every reader — `RTM_GETLINK`, `SIOCGIFFLAGS`, a dump — goes through this, so
/// there is one answer rather than one per caller.
/// # C: O(1)
pub fn dev_get_flags(stored: u32, carrier: bool) -> u32 {
    let base = stored & !(IFF_RUNNING | IFF_LOWER_UP);
    if base & IFF_UP != 0 && carrier { base | IFF_RUNNING | IFF_LOWER_UP } else { base }
}
