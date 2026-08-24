//! `/sys/class/net/<bond>/bonding_slave/<slave>` projections.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bonding::{BondMaster, BondSlaveView};
use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef,
          KResult, VfsError};

use crate::{kobject, DIR_PERM, RO_PERM};

const ATTRS: &[&str] = &["state", "mii_status", "link_failure_count", "perm_hwaddr",
                         "queue_id", "ad_aggregator_id", "ad_actor_oper_port_state",
                         "ad_partner_oper_port_state"];

struct SlaveData { master: Arc<BondMaster>, name: String }

fn view(data: &SlaveData) -> KResult<BondSlaveView> {
    data.master.view().slaves.into_iter().find(|s| s.name == data.name)
        .ok_or(VfsError::Enoent)
}

fn text(v: &BondSlaveView, attr: &str) -> Option<String> {
    Some(match attr {
        "state" => if v.state.is_active() { "active" } else { "backup" }.into(),
        "mii_status" => match v.state.link {
            bonding::LinkState::Up => "up", bonding::LinkState::Fail => "failed",
            bonding::LinkState::Down => "down", bonding::LinkState::Back => "backup",
        }.into(),
        "link_failure_count" => alloc::format!("{}", v.state.link_failure_count),
        "perm_hwaddr" => alloc::format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            v.permanent_mac.0[0], v.permanent_mac.0[1], v.permanent_mac.0[2],
            v.permanent_mac.0[3], v.permanent_mac.0[4], v.permanent_mac.0[5]),
        "queue_id" => alloc::format!("{}", v.state.queue_id),
        "ad_aggregator_id" => if v.lacp { alloc::format!("{}", v.state.agg_id) } else { "N/A".into() },
        "ad_actor_oper_port_state" => if v.lacp { alloc::format!("{}", v.actor_port_state) } else { "N/A".into() },
        "ad_partner_oper_port_state" => if v.lacp { alloc::format!("{}", v.partner_port_state) } else { "N/A".into() },
        _ => return None,
    })
}

struct SlaveAttrOps { data: Arc<SlaveData> }
impl kobject::SysfsOps for SlaveAttrOps {
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        Ok(alloc::format!("{}\n", text(&view(&self.data)?, attr).ok_or(VfsError::Enoent)?).into_bytes())
    }
}

struct SlaveDirOps;
impl InodeOps for SlaveDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<SlaveData>().ok_or(VfsError::Einval)?;
        if !ATTRS.contains(&name) { return Err(VfsError::Enoent); }
        // Preserve the selected slave name; the ops owns the same state object.
        let ops = Arc::new(SlaveAttrOps { data: Arc::new(SlaveData {
            master: Arc::clone(&data.master), name: data.name.clone() }) });
        Ok(kobject::make_named_attr_inode(String::from(name), RO_PERM, ops, 0x5520))
    }
}
impl FileOps for SlaveDirOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let _ = inode.private::<SlaveData>().ok_or(VfsError::Einval)?;
        let mut es = crate::readdir::DirEntries::new(inode);
        for attr in ATTRS { es.push(attr, FileType::Regular); }
        es.emit(ctx)
    }
}

/// Build one canonical slave kobject directory.
pub fn make_slave_inode(master: Arc<BondMaster>, name: String) -> InodeRef {
    InodeBuilder::new(0x5521, mk_mode(FileType::Directory, DIR_PERM),
                      Arc::new(SlaveDirOps), Arc::new(SlaveDirOps))
        .private(Arc::new(SlaveData { master, name })).build()
}

struct SlaveRootData { master: Arc<BondMaster> }
struct SlaveRootOps;
impl InodeOps for SlaveRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<SlaveRootData>().ok_or(VfsError::Einval)?;
        if data.master.view().slaves.iter().any(|s| s.name == name) {
            Ok(make_slave_inode(Arc::clone(&data.master), String::from(name)))
        } else { Err(VfsError::Enoent) }
    }
}
impl FileOps for SlaveRootOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<SlaveRootData>().ok_or(VfsError::Einval)?;
        let mut es = crate::readdir::DirEntries::new(inode);
        for slave in data.master.view().slaves { es.push(&slave.name, FileType::Directory); }
        es.emit(ctx)
    }
}

pub fn make_root(master: Arc<BondMaster>) -> InodeRef {
    InodeBuilder::new(0x5522, mk_mode(FileType::Directory, DIR_PERM),
                      Arc::new(SlaveRootOps), Arc::new(SlaveRootOps))
        .private(Arc::new(SlaveRootData { master })).build()
}
