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
use alloc::vec::Vec;

use vfs::{FileCred, KResult, VfsError};

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

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_identity::{initial, NamespaceKind};

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
}
