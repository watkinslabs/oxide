// Dynamic `net/ipv6/conf`: all/default plus one directory per live interface.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::dentry::{Dentry, DentryOps};
use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, VfsError};

use super::{bound_sysctl_inode, current_net_ns, make_leaf, Leaf, NetInt};
use crate::proc_handler::ProcHandler;

const ROOT_PATH: &str = "/proc/sys/net/ipv6/conf";
const DIR_PERM: u16 = 0o555;
const SPECIAL_NAMES: &[&str] = &["all", "default"];
const DEV_LEAVES: &[(&str, net::netdev::Ipv6ConfKey)] = &[
    ("disable_ipv6", net::netdev::Ipv6ConfKey::DisableIpv6),
    ("optimistic_dad", net::netdev::Ipv6ConfKey::OptimisticDad),
    ("use_optimistic", net::netdev::Ipv6ConfKey::UseOptimistic),
];

enum ConfDirKind {
    All,
    Default,
    Iface {
        owner: network_namespace::NetworkNamespaceRef,
        name: String,
        conf: Arc<net::netdev::Ipv6DevConf>,
    },
}

struct ConfDirData { kind: ConfDirKind }

fn dir_inode(path: &str, kind: ConfDirKind) -> InodeRef {
    InodeBuilder::new(kernfs::dir_ino(path), mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ConfDirOps), Arc::new(ConfDirOps))
        .private(Arc::new(ConfDirData { kind })).build()
}

fn special_leaf(kind: &ConfDirKind, name: &str) -> Option<Leaf> {
    if name == "disable_ipv6" {
        return Some(match kind {
            ConfDirKind::All => Leaf::PerNetIntHook(
                disable_ipv6_all_get, disable_ipv6_all_set, None),
            ConfDirKind::Default => Leaf::PerNetIntHook(
                disable_ipv6_default_get, disable_ipv6_default_set, None),
            ConfDirKind::Iface { .. } => return None,
        });
    }
    let key = match (kind, name) {
        (ConfDirKind::All, "optimistic_dad") => net::net_ns::NetSysctlKey::Ipv6OptimisticDadAll,
        (ConfDirKind::All, "use_optimistic") => net::net_ns::NetSysctlKey::Ipv6UseOptimisticAll,
        (ConfDirKind::Default, "optimistic_dad") => net::net_ns::NetSysctlKey::Ipv6OptimisticDadDefault,
        (ConfDirKind::Default, "use_optimistic") => net::net_ns::NetSysctlKey::Ipv6UseOptimisticDefault,
        _ => return None,
    };
    Some(NetInt(key, None))
}

fn disable_ipv6_all_get(ns: &network_namespace::NetworkNamespaceRef, _key: usize)
    -> Result<i64, ()>
{
    net::sysctl::value(ns, net::net_ns::NetSysctlKey::Ipv6DisableAll).ok_or(())
}

fn disable_ipv6_default_get(ns: &network_namespace::NetworkNamespaceRef, _key: usize)
    -> Result<i64, ()>
{
    net::sysctl::value(ns, net::net_ns::NetSysctlKey::Ipv6DisableDefault).ok_or(())
}

fn disable_ipv6_all_set(ns: &network_namespace::NetworkNamespaceRef, _key: usize, value: i64)
    -> Result<(), ()>
{
    net::sysctl::set_value(ns, net::net_ns::NetSysctlKey::Ipv6DisableDefault, value)?;
    net::sysctl::set_value(ns, net::net_ns::NetSysctlKey::Ipv6DisableAll, value)?;
    net::sock::stack().ifaces.set_ipv6_disabled_all_in(ns.id().as_u64(), value);
    Ok(())
}

fn disable_ipv6_default_set(ns: &network_namespace::NetworkNamespaceRef, _key: usize, value: i64)
    -> Result<(), ()>
{
    net::sysctl::set_value(ns, net::net_ns::NetSysctlKey::Ipv6DisableDefault, value)?;
    Ok(())
}

struct DevIntHandler {
    conf: Arc<net::netdev::Ipv6DevConf>,
    key: net::netdev::Ipv6ConfKey,
}

impl ProcHandler for DevIntHandler {
    fn format(&self) -> Vec<u8> { alloc::format!("{}\n", self.conf.value(self.key)).into_bytes() }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let value = crate::proc_handler::parse_single_i64(src)?;
        self.conf.set_value(self.key, value);
        Ok(())
    }
}

struct ConfDirOps;

impl InodeOps for ConfDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let Some(data) = inode.private::<ConfDirData>() else { return Err(VfsError::Enoent) };
        match &data.kind {
            ConfDirKind::All | ConfDirKind::Default => special_leaf(&data.kind, name)
                .map(|leaf| make_leaf(&leaf)).ok_or(VfsError::Enoent),
            ConfDirKind::Iface { conf, .. } => DEV_LEAVES.iter()
                .find(|(leaf, _)| *leaf == name)
                .map(|(_, key)| bound_sysctl_inode(Arc::new(DevIntHandler {
                    conf: Arc::clone(conf), key: *key,
                }))).ok_or(VfsError::Enoent),
        }
    }

    fn child_d_op(&self, _inode: &Inode, _name: &str) -> Option<&'static DentryOps> {
        Some(&IPV6_CONF_DENTRY_OPS)
    }
}

impl FileOps for ConfDirOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let Some(data) = inode.private::<ConfDirData>() else { return Err(VfsError::Enoent) };
        let names: Vec<(String, FileType)> = match &data.kind {
            ConfDirKind::All | ConfDirKind::Default => crate::readdir::typed(
                &["disable_ipv6", "optimistic_dad", "use_optimistic"], FileType::Regular),
            ConfDirKind::Iface { .. } => crate::readdir::typed(
                &DEV_LEAVES.iter().map(|(name, _)| *name).collect::<Vec<_>>(), FileType::Regular),
        };
        crate::readdir::emit_resolved(names, |name| inode.lookup(name).ok().map(|child| child.ino()), ctx)
    }
}

struct ConfRootOps;

impl InodeOps for ConfRootOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let kind = match name {
            "all" => ConfDirKind::All,
            "default" => ConfDirKind::Default,
            _ => {
                let owner = current_net_ns();
                let conf = net::sock::stack().ifaces
                    .ipv6_conf_by_name_in(name, owner.id().as_u64()).ok_or(VfsError::Enoent)?;
                ConfDirKind::Iface { owner, name: name.to_string(), conf }
            }
        };
        Ok(dir_inode(&alloc::format!("{ROOT_PATH}/{name}"), kind))
    }

    fn child_d_op(&self, _inode: &Inode, _name: &str) -> Option<&'static DentryOps> {
        Some(&IPV6_CONF_DENTRY_OPS)
    }
}

impl FileOps for ConfRootOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let owner = current_net_ns();
        let mut names: Vec<String> = SPECIAL_NAMES.iter().map(|name| (*name).to_string()).collect();
        names.extend(net::sock::stack().ifaces.snapshot_in_ns(owner.id().as_u64())
            .into_iter().map(|iface| iface.name));
        crate::readdir::emit_resolved(names.into_iter().map(|name| (name, FileType::Directory)),
            |name| inode.lookup(name).ok().map(|child| child.ino()), ctx)
    }
}

fn revalidate(dentry: &Arc<Dentry>, _reval: bool) -> bool {
    if dentry.inode().is_none() { return false; }
    let mut current = Some(dentry.as_ref());
    while let Some(node) = current {
        if let Some(inode) = node.inode() {
            if let Some(data) = inode.private::<ConfDirData>() {
                let ConfDirKind::Iface { owner, name, conf } = &data.kind else { return true };
                if current_net_ns().id() != owner.id() { return false; }
                return net::sock::stack().ifaces
                    .ipv6_conf_by_name_in(name, owner.id().as_u64())
                    .is_some_and(|live| Arc::ptr_eq(&live, conf));
            }
        }
        current = node.parent().map(|parent| parent.as_ref());
    }
    true
}

static IPV6_CONF_DENTRY_OPS: DentryOps = DentryOps {
    d_revalidate: Some(revalidate), d_hash: None, d_compare: None,
    d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None,
    d_dname: None, d_init: None, d_prune: None,
};

pub(super) fn register() {
    let inode = InodeBuilder::new(kernfs::dir_ino(ROOT_PATH),
        mk_mode(FileType::Directory, DIR_PERM), Arc::new(ConfRootOps), Arc::new(ConfRootOps)).build();
    crate::reg::register(ROOT_PATH, inode);
}
