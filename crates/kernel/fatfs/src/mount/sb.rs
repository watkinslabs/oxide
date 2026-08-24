//! `statfs`, the option tail, and flushing at unmount.
//!
//! `statfs` is the one caller of the free-cluster count, and the count is why
//! this exists at all: FAT keeps no free-space accounting beyond the FAT32
//! information sector's hint, so the only authoritative answer is a scan of
//! the whole table. It is taken ONCE, on the first question that needs it, and
//! maintained by every allocation and release from then on — which is what
//! makes `df` on a freshly mounted volume cost a table walk and every later
//! one cost nothing.

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::superblock::{SbStatFs, SuperOps};
use vfs::export::fid::{Fid, fid_len_for_type};
use vfs::{Inode, InodeRef, KResult, SuperBlock};

use super::{errno_to_vfs, FatFs, MSDOS_SUPER_MAGIC};

/// The superblock operations of one mounted volume.
pub struct FatSuperOps {
    pub(crate) fs: Arc<FatFs>,
}

/// Linux's `FILEID_FAT_WITHOUT_PARENT` and `FILEID_FAT_WITH_PARENT`.
const FAT_WITHOUT_PARENT: i32 = 0x71;
const FAT_WITH_PARENT: i32 = 0x72;
const FAT_FID_WORDS: u32 = 3;
const FAT_FID_WORDS_PARENT: u32 = 5;

fn fat_fid_len(parent: bool) -> u32 {
    if parent { FAT_FID_WORDS_PARENT * 4 } else { FAT_FID_WORDS * 4 }
}

fn encode_fat_fid(fid: &Fid, buf: &mut [u8]) -> (u32, i32) {
    buf[0..4].copy_from_slice(&fid.generation.to_le_bytes());
    buf[4..8].copy_from_slice(&(fid.ino as u32).to_le_bytes());
    buf[8..10].copy_from_slice(&((fid.ino >> 32) as u16).to_le_bytes());
    if let Some((parent, generation)) = fid.parent {
        buf[10..12].copy_from_slice(&((parent >> 32) as u16).to_le_bytes());
        buf[12..16].copy_from_slice(&(parent as u32).to_le_bytes());
        buf[16..20].copy_from_slice(&generation.to_le_bytes());
        (fat_fid_len(true), FAT_WITH_PARENT)
    } else {
        (fat_fid_len(false), FAT_WITHOUT_PARENT)
    }
}

fn decode_fat_fid(bytes: &[u8], handle_type: i32) -> Result<Fid, syscall::errno::Errno> {
    let want = match handle_type {
        FAT_WITHOUT_PARENT => fat_fid_len(false),
        FAT_WITH_PARENT => fat_fid_len(true),
        _ => return Err(syscall::errno::Errno::Estale),
    };
    if bytes.len() != want as usize { return Err(syscall::errno::Errno::Estale); }
    let generation = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
    let low = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
    let high = u16::from_le_bytes(bytes[8..10].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
    let position = u64::from(low) | (u64::from(high) << 32);
    let parent = if handle_type == FAT_WITH_PARENT {
        let parent_high = u16::from_le_bytes(bytes[10..12].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
        let parent_low = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
        let parent_generation = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| syscall::errno::Errno::Estale)?);
        Some((u64::from(parent_low) | (u64::from(parent_high) << 32), parent_generation))
    } else { None };
    Ok(Fid { ino: position, generation, parent })
}

impl SuperOps for FatSuperOps {
    fn export_fid_len(&self, connectable: bool, is_dir: bool) -> u32 {
        if self.fs.options().nfs == crate::opts::Nfs::NostaleRo {
            fat_fid_len(connectable && !is_dir)
        } else {
            vfs::export::fid::encoded_fid_len(connectable, is_dir)
        }
    }

    fn export_encode_fh(&self, inode: &InodeRef, parent: Option<(vfs::Ino, u32)>, buf: &mut [u8])
        -> (u32, i32)
    {
        if self.fs.options().nfs != crate::opts::Nfs::NostaleRo {
            return vfs::export::fid::encode_fid_into(
                &Fid { ino: inode.ino(), generation: inode.i_generation(), parent }, buf);
        }
        let node = match inode.private::<super::node::FatNode>() {
            Some(node) => node,
            None => return (0, 0),
        };
        // FAT's parent field is the parent's directory start cluster; zero is
        // the fixed root. The generic VFS identity already tags cluster dirs.
        let parent = parent.map(|(ino, generation)| {
            let cluster = if ino == crate::ident::ROOT_INO { 0 } else { ino & u64::from(u32::MAX) };
            (cluster, generation)
        });
        encode_fat_fid(&Fid {
            ino: super::node::handle_position(node.entry.as_ref(), node.parent, node.slot),
            generation: inode.i_generation(),
            parent,
        }, buf)
    }

    fn export_fid_len_for_type(&self, handle_type: i32) -> Option<u32> {
        if self.fs.options().nfs == crate::opts::Nfs::NostaleRo {
            match handle_type {
                FAT_WITHOUT_PARENT => Some(fat_fid_len(false)),
                FAT_WITH_PARENT => Some(fat_fid_len(true)),
                _ => None,
            }
        } else { fid_len_for_type(handle_type) }
    }

    fn export_decode_fh(&self, bytes: &[u8], handle_type: i32)
        -> Result<Fid, syscall::errno::Errno>
    {
        if self.fs.options().nfs == crate::opts::Nfs::NostaleRo {
            decode_fat_fid(bytes, handle_type)
        } else { vfs::export::fid::decode_fid(bytes, handle_type) }
    }

    fn fh_to_dentry(&self, sb: &SuperBlock, ino: vfs::Ino, generation: u32)
        -> Option<InodeRef>
    {
        if self.fs.options().nfs == crate::opts::Nfs::NostaleRo {
            self.fs.inode_for_handle(sb, ino, generation)
        } else { vfs::export::ilookup_generation(sb, ino, generation) }
    }

    fn fh_to_parent(&self, sb: &SuperBlock, ino: vfs::Ino, generation: u32)
        -> Option<InodeRef>
    {
        if self.fs.options().nfs == crate::opts::Nfs::NostaleRo {
            self.fs.directory_for_handle(sb, ino, generation)
        } else { vfs::export::ilookup_generation(sb, ino, generation) }
    }

    // Linux installs the ordinary FAT export owner even with the internal
    // default (`nfs=0`); `nfs=nostale_ro` replaces only its codec and lookup.
    fn export_can_decode_fh(&self) -> bool { true }

    /// The unit is the CLUSTER, not the sector: it is what an allocation
    /// hands out, so it is the unit in which a volume is full.
    fn statfs(&self) -> KResult<SbStatFs> {
        let mut v = self.fs.volume.lock();
        let free = u64::from(v.free_clusters_counted());
        let opts = *v.options();
        Ok(SbStatFs {
            f_type: MSDOS_SUPER_MAGIC,
            f_bsize: u32::try_from(v.geometry().cluster_bytes()).unwrap_or(u32::MAX),
            f_blocks: u64::from(v.total_clusters()),
            f_bfree: free,
            // FAT reserves nothing for a privileged caller, so what is free is
            // what is available.
            f_bavail: free,
            // A filesystem with no inode table has no inode count to report,
            // and the reference leaves both at zero rather than inventing one.
            f_files: 0,
            f_ffree: 0,
            f_fsid: 0,
            f_flags: 0,
            f_namelen: opts.name_max(),
            f_frsize: 0,
        })
    }

    fn show_options(&self) -> String { crate::opts::show(self.fs.volume.lock().options()) }

    /// Push the table, the information sector and the dirty flag.
    ///
    /// The table goes first: the information sector's count describes it, and
    /// a count written ahead of the table it counts describes a state that was
    /// never on the medium.
    fn sync_fs(&self, _wait: bool) -> KResult<()> {
        if self.fs.evict_error.swap(false, Ordering::AcqRel) { return Err(vfs::VfsError::Eio); }
        let mut v = self.fs.volume.lock();
        if !v.writable() { return Ok(()); }
        v.flush_table().map_err(errno_to_vfs)?;
        v.flush_fsinfo().map_err(errno_to_vfs)
    }

    /// Release a linkless inode's cluster chain only after its final open
    /// reference has gone. # C: O(chain length)
    fn evict_inode(&self, inode: &Inode) {
        if let Some(node) = inode.private::<super::node::FatNode>() {
            let cluster = node.take_release();
            if cluster != 0 {
                if self.fs.volume.lock().release_chain(cluster).is_err() {
                    self.fs.evict_error.store(true, Ordering::Release);
                }
            }
        }
        inode.set_state(vfs::inode::I_FREEING | vfs::inode::I_CLEAR, vfs::inode::I_DIRTY);
    }
}
