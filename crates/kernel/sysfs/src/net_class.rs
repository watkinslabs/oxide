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

const CLASS_TARGET_PREFIX: &str = "../../";
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
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>, Option<Arc<drv::Device>>)> {
    let stack = net::sock::stack();
    stack.ifaces.snapshot_sysfs_in_ns(INITIAL_NET_NS)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn snapshot_net_devs() -> Vec<(net::NetIfaceId, String, Arc<dyn net::NetDev>, Option<Arc<drv::Device>>)> {
    Vec::new()
}

fn iface_canon(parent: &drv::Device, name: &str) -> Option<String> {
    Some(alloc::format!("{}/net/{}", drv::device_canon_exact(parent)?, name))
}

/// Relative class symlink target for one live network interface. # C: O(depth)
pub(crate) fn class_target(name: &str, parent: Option<&Arc<drv::Device>>) -> Option<String> {
    match parent {
        Some(parent) => Some(alloc::format!("{CLASS_TARGET_PREFIX}{}", iface_canon(parent, name)?)),
        None => Some(alloc::format!("../../devices/virtual/net/{name}")),
    }
}

fn iface_devpath(data: &NetIfaceData) -> Option<String> {
    match data.parent.as_ref() {
        Some(parent) => Some(alloc::format!("/{}", iface_canon(parent, &data.name)?)),
        None => Some(alloc::format!("/devices/virtual/net/{}", data.name)),
    }
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
/// Drop stale class and exact physical-parent netdev dentries. # C: O(depth)
pub(crate) fn invalidate_netdev_paths(name: &str, parent: Option<&Arc<drv::Device>>) {
    for path in [CLASS_NET_PATH, DEVICES_NET_PATH] {
        crate::drop_cached(&alloc::format!("{path}/{name}"));
    }
    let Some(parent) = parent else { return; };
    let Some(canon) = iface_canon(parent, name) else { return; };
    let physical = alloc::format!("/sys/{canon}");
    crate::drop_cached(&physical);
    let net_dir = physical.rsplit_once('/').map(|(dir, _)| dir).unwrap_or(physical.as_str());
    crate::drop_cached(net_dir);
}

struct SysClassNetOps;

impl InodeOps for SysClassNetOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if let Some((_, current, _, parent)) = snapshot_net_devs().iter()
            .find(|(_, current, _, _)| current == name)
        {
            return Ok(crate::make_symlink_inode(
                class_target(current, parent.as_ref()).ok_or(VfsError::Enoent)?.into_bytes(),
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
        let (_, _, dev, parent) = snapshot_net_devs().into_iter()
            .find(|(_, current, _, parent)| current == name && parent.is_none())
            .ok_or(VfsError::Enoent)?;
        Ok(make_net_iface_inode(String::from(name), dev, parent))
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
        crate::readdir::emit_names(inode, ctx, snap.iter().filter(|d| d.3.is_none()).map(|d| d.1.as_str()),
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
    parent: Option<Arc<drv::Device>>,
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
        let devpath = iface_devpath(self).ok_or(VfsError::Enoent)?;
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
            parent: data.parent.clone(),
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
        if name == "device" {
            let parent = data.parent.as_ref().ok_or(VfsError::Enoent)?;
            return Ok(crate::bus::make_device_link_inode(Arc::clone(parent), b"../..".to_vec()));
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
        if inode.private::<NetIfaceData>().and_then(|data| data.parent.as_ref()).is_some() {
            es.push("device", FileType::Symlink);
        }
        es.emit(ctx)
    }
}

pub(crate) fn make_net_iface_inode(name: String, dev: Arc<dyn net::NetDev>,
                                   parent: Option<Arc<drv::Device>>) -> InodeRef {
    InodeBuilder::new(
        ids::KOBJ_ROOT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(NetIfaceOps),
        Arc::new(NetIfaceOps),
    )
    .private(Arc::new(NetIfaceData { name, dev, parent }))
    .build()
}

fn parented_iface(parent: &Arc<drv::Device>, name: &str)
    -> Option<(Arc<dyn net::NetDev>, Arc<drv::Device>)>
{
    snapshot_net_devs().into_iter().find_map(|(_, current, dev, iface_parent)| {
        if current != name { return None; }
        let iface_parent = iface_parent?;
        Arc::ptr_eq(&iface_parent, parent).then_some((dev, iface_parent))
    })
}

/// Whether a model device currently owns a physical network interface. # C: O(N)
pub(crate) fn has_parented_net(parent: &Arc<drv::Device>) -> bool {
    snapshot_net_devs().iter().any(|(_, _, _, iface_parent)| {
        iface_parent.as_ref().is_some_and(|iface_parent| Arc::ptr_eq(iface_parent, parent))
    })
}

struct ParentNetData { parent: Arc<drv::Device> }

struct ParentNetOps;
impl InodeOps for ParentNetOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let parent = &inode.private::<ParentNetData>().ok_or(VfsError::Einval)?.parent;
        let (dev, parent) = parented_iface(parent, name).ok_or(VfsError::Enoent)?;
        iface_canon(&parent, name).ok_or(VfsError::Enoent)?;
        Ok(make_net_iface_inode(String::from(name), dev, Some(parent)))
    }
}
impl FileOps for ParentNetOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let parent = &inode.private::<ParentNetData>().ok_or(VfsError::Einval)?.parent;
        drv::device_canon_exact(parent).ok_or(VfsError::Enoent)?;
        let names = snapshot_net_devs().into_iter().filter_map(|(_, name, _, iface_parent)| {
            iface_parent.filter(|iface_parent| Arc::ptr_eq(iface_parent, parent)).map(|_| name)
        }).collect::<Vec<_>>();
        crate::readdir::emit_names(inode, ctx, names.iter().map(|name| name.as_str()), FileType::Directory)
    }
}

/// Build the `net` directory nested below one transport device. # C: O(1)
pub(crate) fn make_parent_net_inode(parent: Arc<drv::Device>) -> InodeRef {
    InodeBuilder::new(ids::KOBJ_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ParentNetOps), Arc::new(ParentNetOps))
        .private(Arc::new(ParentNetData { parent }))
        .build()
}
