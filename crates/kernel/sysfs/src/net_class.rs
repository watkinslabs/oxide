// `/sys/class/net` and `/sys/devices/virtual/net` projections.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{
    mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef,
    KResult, VfsError,
};

use crate::kobject::{Attribute, AttrGroup, SysfsOps};
use crate::{ids, net_stats, VecFmt, DIR_PERM, RO_PERM, RW_PERM};

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
#[cfg(target_os = "oxide-kernel")]
const INITIAL_NET_NS: u64 = 0;
const IFACE_BODY_CAPACITY: usize = 32;

const CLASS_TARGET_PREFIX: &str = "../../devices/virtual/net/";
#[cfg(target_os = "oxide-kernel")]
const CLASS_NET_PATH: &str = "/sys/class/net";
#[cfg(target_os = "oxide-kernel")]
const DEVICES_NET_PATH: &str = "/sys/devices/virtual/net";
const NET_SUBSYSTEM_TARGET: &[u8] = b"../../../../class/net";

const ADDR_ASSIGN_PERMANENT: &[u8] = b"0\n";
const ETHER_ADDR_LEN: &[u8] = b"6\n";
const ETHER_BROADCAST: &[u8] = b"ff:ff:ff:ff:ff:ff\n";
const ETHER_DUPLEX: &[u8] = b"full\n";
const ETHER_FLAGS: &[u8] = b"0x1003\n";
const ETHER_SPEED: &[u8] = b"10000\n";
const IFACE_CARRIER: &[u8] = b"1\n";
const IFACE_DEV_ID: &[u8] = b"0x0\n";
const IFACE_DEV_PORT: &[u8] = b"0\n";
const IFACE_TX_QUEUE_LEN: &[u8] = b"1000\n";
const LOOPBACK_DUPLEX: &[u8] = b"unknown\n";
const LOOPBACK_FLAGS: &[u8] = b"0x49\n";
const LOOPBACK_OPERSTATE: &[u8] = b"unknown\n";
const LOOPBACK_SPEED: &[u8] = b"-1\n";
const NAME_ASSIGN_ENUM: &[u8] = b"4\n";

#[cfg(target_os = "oxide-kernel")]
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>)> {
    let stack = net::sock::stack();
    stack.ifaces.snapshot_in_ns(INITIAL_NET_NS).into_iter().filter_map(|snap| {
        stack.ifaces.lookup_in_ns(snap.id, INITIAL_NET_NS)
            .map(|dev| (snap.id, snap.name, dev))
    }).collect()
}

#[cfg(not(target_os = "oxide-kernel"))]
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>)> {
    Vec::new()
}

#[cfg(target_os = "oxide-kernel")]
fn lookup_net_ifindex(name: &str) -> u32 {
    net::sock::stack().ifaces.lookup_name(name).map(|(id, _)| id.raw()).unwrap_or(0)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn lookup_net_ifindex(_name: &str) -> u32 {
    0
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) fn invalidate_netdev_paths(name: &str) {
    for path in [CLASS_NET_PATH, DEVICES_NET_PATH] {
        crate::drop_cached(&alloc::format!("{path}/{name}"));
    }
}

struct SysClassNetOps;

impl InodeOps for SysClassNetOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if snapshot_net_devs().iter().any(|(_, current, _)| current == name) {
            return Ok(crate::make_symlink_inode(
                alloc::format!("{CLASS_TARGET_PREFIX}{name}").into_bytes(),
            ));
        }
        Err(VfsError::Enoent)
    }
}

impl FileOps for SysClassNetOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = snapshot_net_devs();
        #[cfg(feature = "debug-udevdb")]
        if ctx.pos == 0 {
            klog::write_raw(b"[UDEVDB class-net-walk n=");
            klog::write_dec_u64(snap.len() as u64);
            klog::write_raw(b"]\n");
        }
        crate::readdir::emit_names(inode, ctx, snap.iter().map(|d| d.1.as_str()),
            FileType::Symlink)
    }
}

pub(crate) fn make_sys_class_net_inode() -> InodeRef {
    InodeBuilder::new(
        ids::ROOT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassNetOps),
        Arc::new(SysClassNetOps),
    ).build()
}

struct SysDevicesVirtualNetOps;

impl InodeOps for SysDevicesVirtualNetOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (_, _, dev) = snapshot_net_devs().into_iter()
            .find(|(_, current, _)| current == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_net_iface_inode(String::from(name), dev))
    }
}

impl FileOps for SysDevicesVirtualNetOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let snap = snapshot_net_devs();
        #[cfg(feature = "debug-udevdb")]
        if ctx.pos == 0 {
            klog::write_raw(b"[UDEVDB devices-virtual-net-walk n=");
            klog::write_dec_u64(snap.len() as u64);
            klog::write_raw(b"]\n");
        }
        crate::readdir::emit_names(inode, ctx, snap.iter().map(|d| d.1.as_str()),
            FileType::Directory)
    }
}

pub(crate) fn make_sys_devices_virtual_net_inode() -> InodeRef {
    InodeBuilder::new(
        ids::CLASS,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualNetOps),
        Arc::new(SysDevicesVirtualNetOps),
    ).build()
}

struct NetIfaceData {
    name: String,
    dev: Arc<dyn net::NetDev>,
}

fn arphrd(name: &str) -> u16 {
    if name == "lo" { ARPHRD_LOOPBACK } else { ARPHRD_ETHER }
}

fn iface_body(data: &NetIfaceData, leaf: &str) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(IFACE_BODY_CAPACITY);
    let hardware_type = arphrd(&data.name);
    match leaf {
        "address" => {
            let mac = data.dev.mac().0;
            let _ = core::fmt::Write::write_fmt(
                &mut VecFmt(&mut body),
                format_args!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                ),
            );
        }
        "broadcast" => body.extend_from_slice(ETHER_BROADCAST),
        "mtu" => {
            let _ = core::fmt::Write::write_fmt(
                &mut VecFmt(&mut body),
                format_args!("{}\n", data.dev.mtu()),
            );
        }
        "operstate" => body.extend_from_slice(if hardware_type == ARPHRD_LOOPBACK {
            LOOPBACK_OPERSTATE
        } else {
            b"up\n"
        }),
        "type" => {
            let _ = core::fmt::Write::write_fmt(
                &mut VecFmt(&mut body),
                format_args!("{hardware_type}\n"),
            );
        }
        "flags" => body.extend_from_slice(if hardware_type == ARPHRD_LOOPBACK {
            LOOPBACK_FLAGS
        } else {
            ETHER_FLAGS
        }),
        "carrier" => body.extend_from_slice(IFACE_CARRIER),
        "speed" => body.extend_from_slice(if hardware_type == ARPHRD_LOOPBACK {
            LOOPBACK_SPEED
        } else {
            ETHER_SPEED
        }),
        "duplex" => body.extend_from_slice(if hardware_type == ARPHRD_LOOPBACK {
            LOOPBACK_DUPLEX
        } else {
            ETHER_DUPLEX
        }),
        "ifindex" => {
            let _ = core::fmt::Write::write_fmt(
                &mut VecFmt(&mut body),
                format_args!("{}\n", lookup_net_ifindex(&data.name)),
            );
        }
        "tx_queue_len" => body.extend_from_slice(IFACE_TX_QUEUE_LEN),
        "addr_len" => body.extend_from_slice(ETHER_ADDR_LEN),
        "addr_assign_type" => body.extend_from_slice(ADDR_ASSIGN_PERMANENT),
        "name_assign_type" => body.extend_from_slice(NAME_ASSIGN_ENUM),
        "dev_id" => body.extend_from_slice(IFACE_DEV_ID),
        "dev_port" => body.extend_from_slice(IFACE_DEV_PORT),
        _ => return None,
    }
    Some(body)
}

const NET_IFACE_ATTRS: &[Attribute] = &[
    Attribute { name: "address",          mode: RO_PERM },
    Attribute { name: "broadcast",        mode: RO_PERM },
    Attribute { name: "mtu",              mode: RO_PERM },
    Attribute { name: "operstate",        mode: RO_PERM },
    Attribute { name: "type",             mode: RO_PERM },
    Attribute { name: "flags",            mode: RO_PERM },
    Attribute { name: "carrier",          mode: RO_PERM },
    Attribute { name: "speed",            mode: RO_PERM },
    Attribute { name: "duplex",           mode: RO_PERM },
    Attribute { name: "ifindex",          mode: RO_PERM },
    Attribute { name: "tx_queue_len",     mode: RO_PERM },
    Attribute { name: "addr_len",         mode: RO_PERM },
    Attribute { name: "addr_assign_type", mode: RO_PERM },
    Attribute { name: "name_assign_type", mode: RO_PERM },
    Attribute { name: "dev_id",           mode: RO_PERM },
    Attribute { name: "dev_port",         mode: RO_PERM },
    Attribute { name: "uevent",           mode: RW_PERM },
];
static NET_IFACE_GROUP: AttrGroup = AttrGroup { attrs: NET_IFACE_ATTRS };

impl SysfsOps for NetIfaceData {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        if attr == "uevent" {
            return Ok(alloc::format!(
                "INTERFACE={}\nIFINDEX={}\n",
                self.name,
                lookup_net_ifindex(&self.name),
            ).into_bytes());
        }
        iface_body(self, attr).ok_or(VfsError::Enoent)
    }

    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        if attr != "uevent" { return Err(VfsError::Erofs); }
        #[cfg(feature = "debug-udevdb")]
        {
            klog::write_raw(b"[UDEVDB net-uevent-store if=");
            klog::write_raw(self.name.as_bytes());
            klog::write_raw(b" action=");
            klog::write_raw(crate::uevent_action(buf).as_bytes());
            klog::write_raw(b"]\n");
        }
        let devpath = alloc::format!("/devices/virtual/net/{}", self.name);
        let iface = alloc::format!("INTERFACE={}", self.name);
        let ifindex = alloc::format!("IFINDEX={}", lookup_net_ifindex(&self.name));
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(buf),
            &devpath,
            "net",
            &[&iface, &ifindex],
        );
        Ok(buf.len())
    }
}

struct NetIfaceOps;

impl NetIfaceOps {
    fn ops(data: &NetIfaceData) -> Arc<dyn SysfsOps> {
        Arc::new(NetIfaceData {
            name: data.name.clone(),
            dev: Arc::clone(&data.dev),
        })
    }
}

impl InodeOps for NetIfaceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<NetIfaceData>().ok_or(VfsError::Einval)?;
        if name == "statistics" {
            return Ok(net_stats::make_net_stats_inode(Arc::clone(&data.dev)));
        }
        if name == "subsystem" {
            return Ok(crate::make_symlink_inode(NET_SUBSYSTEM_TARGET.to_vec()));
        }
        let attr = NET_IFACE_GROUP.find(name).ok_or(VfsError::Enoent)?;
        let ino: Ino = if name == "uevent" { ids::UEVENT } else { ids::ATTR };
        Ok(crate::kobject::make_attr_inode(attr, NetIfaceOps::ops(data), ino))
    }
}

impl FileOps for NetIfaceOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut es = crate::readdir::DirEntries::new(inode);
        for attr in NET_IFACE_GROUP.attrs.iter() { es.push(attr.name, FileType::Regular); }
        es.push("statistics", FileType::Directory);
        es.push("subsystem", FileType::Symlink);
        es.emit(ctx)
    }
}

pub(crate) fn make_net_iface_inode(name: String, dev: Arc<dyn net::NetDev>) -> InodeRef {
    InodeBuilder::new(
        ids::KOBJ_ROOT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(NetIfaceOps),
        Arc::new(NetIfaceOps),
    )
    .private(Arc::new(NetIfaceData { name, dev }))
    .build()
}
