// `/proc/kcore` — a core file of the RUNNING kernel's address space, generated
// on read. Nothing is stored: the header, the program-header table and the
// notes are computed per read, and the described bytes come from live memory.
//
// This is the file a kernel debugger opens. It learns the described regions
// from the program headers, the text base from the notes, and then SEEKS to the
// offset an address maps to. So the two things that must be right are the byte
// layout of the description and the offset arithmetic — both live in the
// ungated modules below, where they are checked against a synthetic region list
// instead of against a boot.
//
// Module manifest:
// - `layout`: ELF header, program-header table, offset arithmetic.
// - `notes`:  the note segment, including the core-information note that names
//             the kernel's text base.
// - `read`:   offset-addressable assembly of the whole file.
// - `live`:   kernel-only — this machine's real regions and the memory read.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, File, FileCred, FileOps, FileType, Inode, InodeBuilder,
    InodeRef, KResult, VfsError};

pub mod layout;
pub mod notes;
pub mod read;
#[cfg(target_os = "oxide-kernel")]
pub mod live;

/// Mode the file carries: readable by its owner only.
///
/// The contents are every byte of kernel memory, so the DAC bits are the outer
/// of two gates and the capability check at open is the one that decides.
pub const KCORE_MODE: u16 = 0o400;

/// One described range of the kernel's address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    /// Kernel virtual address the range starts at.
    pub vaddr: u64,
    /// Length in bytes.
    pub size: u64,
    /// Physical address, when the range has one.
    pub paddr: Option<u64>,
}

/// Everything one read of the file is computed from.
pub struct Map {
    /// Base the linear address-to-offset mapping is taken from. Every described
    /// address lies above it.
    pub page_offset: u64,
    /// `e_machine`.
    pub machine: u16,
    /// The described regions, in the order their program headers appear.
    pub regions: Vec<Region>,
    /// The note segment's bytes.
    pub notes: Vec<u8>,
}

/// May this opener read the file?
///
/// The contents are the whole of kernel memory — every key, every credential,
/// and the addresses that defeat kernel-address randomisation — so raw-hardware
/// authority is what it takes. Refusing with EPERM rather than EACCES is what a
/// caller distinguishes from a mode failure.
/// # C: O(1)
pub fn open_permitted(cred: &FileCred) -> KResult<()> {
    if cred.has_cap(sched::cap::SYS_RAWIO) { Ok(()) } else { Err(VfsError::Eperm) }
}

struct KcoreOps {
    map: fn() -> Map,
    fetch: fn(u64, &mut [u8]),
}

impl FileOps for KcoreOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &File) -> bool { true }

    /// Raw hardware authority is checked at open, so a descriptor handed to a
    /// process that has since dropped it keeps working. # C: O(1)
    fn on_open_file(&self, file: &File) -> KResult<()> {
        open_permitted(file.file_cred())
    }

    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(read::read_at(&(self.map)(), off, buf, self.fetch))
    }

    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Eperm)
    }
}

/// Build `/proc/kcore` around the live machine providers. Keeping the file
/// operations here makes its open gate exercisable on the hosted target.
/// # C: O(N regions)
fn make_inode(map: fn() -> Map, fetch: fn(u64, &mut [u8])) -> InodeRef {
    let size = layout::file_size(&map());
    InodeBuilder::new(crate::ids::KCORE as vfs::Ino,
        mk_mode(FileType::Regular, KCORE_MODE), default_inode_ops(),
        Arc::new(KcoreOps { map, fetch }))
        .size(size)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_identity::{initial, NamespaceKind};

    fn test_map() -> Map {
        Map {
            page_offset: 0x1000,
            machine: layout::EM_X86_64,
            regions: alloc::vec![Region { vaddr: 0x1000, size: 0x1000, paddr: Some(0) }],
            notes: Vec::new(),
        }
    }

    fn test_fetch(_vaddr: u64, dst: &mut [u8]) { dst.fill(0x5a); }

    #[test]
    fn opening_kcore_takes_raw_hardware_authority() {
        let user = initial(NamespaceKind::User);
        let bare = FileCred::new(vfs::Cred::root(), user.clone(), 0);
        assert_eq!(open_permitted(&bare), Err(VfsError::Eperm));
        // A different capability is not a substitute: this file is not
        // administrative access, it is raw memory.
        let other = FileCred::new(vfs::Cred::root(), user.clone(),
            1u64 << sched::cap::SYS_ADMIN);
        assert_eq!(open_permitted(&other), Err(VfsError::Eperm));
        let raw = FileCred::new(vfs::Cred::root(), user, 1u64 << sched::cap::SYS_RAWIO);
        assert_eq!(open_permitted(&raw), Ok(()));
    }

    #[test]
    fn kcore_is_readable_by_its_owner_only() {
        assert_eq!(KCORE_MODE, 0o400);
    }

    #[test]
    fn kcore_inode_open_runs_the_rawio_gate() {
        let inode = make_inode(test_map, test_fetch);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let user = initial(NamespaceKind::User);
        let denied = vfs::file::open_file_at(inode, dentry, vfs::OpenFlags::O_RDONLY, 0,
            FileCred::new(vfs::Cred::root(), user.clone(), 0), None);
        assert!(matches!(denied, Err(VfsError::Eperm)));

        let inode = make_inode(test_map, test_fetch);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let opened = vfs::file::open_file_at(inode, dentry, vfs::OpenFlags::O_RDONLY, 0,
            FileCred::new(vfs::Cred::root(), user, 1u64 << sched::cap::SYS_RAWIO), None);
        assert!(opened.is_ok());
    }
}
