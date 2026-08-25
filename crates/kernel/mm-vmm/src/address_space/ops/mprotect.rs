use alloc::vec::Vec;

use hal::UserVirtAddr;
use crate::vma::{Vma, VmaFlags, VmaProt};
use crate::{Error, KResult};

use super::super::layout::{end_of, end_of_raw, validate_aligned, validate_len};
use super::super::AddressSpace;

/// One VMA subrange whose page-table permissions must follow a successful
/// VMA-side mprotect transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MprotectStep {
    pub start: UserVirtAddr,
    pub len: usize,
    pub prot: VmaProt,
    pub pkey: u8,
}

/// Linux mprotect may change an earlier VMA before a later VMA fails.
#[derive(Debug, Eq, PartialEq)]
pub struct MprotectOutcome {
    pub steps: Vec<MprotectStep>,
    pub error: Option<Error>,
}

impl AddressSpace {

    pub fn mprotect(
        &self,
        addr: UserVirtAddr,
        len: usize,
        prot: VmaProt,
    ) -> KResult<()> {
        let outcome = self.mprotect_user(addr, len, prot, false, &mut |v: &Vma| v.pkey)?;
        match outcome.error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Apply Linux `do_mprotect_pkey`'s per-VMA permission ladder while the
    /// VMA write lock stays held. Earlier steps remain committed if a later
    /// hole, VM_MAY, MDWE, or mseal check fails.
    ///
    /// `key_for` decides the protection key each VMA carries afterwards, and
    /// runs per VMA because that decision reads the VMA it is running over —
    /// its current key and whether it was execute-only.
    /// # C: O(K log N)
    pub fn mprotect_user(
        &self,
        addr: UserVirtAddr,
        len: usize,
        requested: VmaProt,
        read_implies_exec: bool,
        key_for: &mut dyn FnMut(&Vma) -> u8,
    ) -> KResult<MprotectOutcome> {
        self.mprotect_user_with_security(addr, len, requested, read_implies_exec,
            &mut |_, _| Ok(()), key_for)
    }

    pub fn mprotect_user_with_security(
        &self,
        addr: UserVirtAddr,
        len: usize,
        requested: VmaProt,
        read_implies_exec: bool,
        security: &mut dyn FnMut(&Vma, VmaProt) -> Result<(), Error>,
        key_for: &mut dyn FnMut(&Vma) -> u8,
    ) -> KResult<MprotectOutcome> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        let count = tree.iter().filter(|vma| {
            vma.end.as_u64() > addr.as_u64() && vma.start.as_u64() < end.as_u64()
        }).count();
        let mut steps = Vec::new();
        steps.try_reserve(count).map_err(|_| Error::NoMem)?;
        let mut cursor = addr.as_u64();
        let mut error = None;
        while cursor < end.as_u64() {
            let Some(vma) = tree.iter().find(|vma| vma.end.as_u64() > cursor) else {
                error = Some(Error::NoMem);
                break;
            };
            if vma.start.as_u64() > cursor {
                error = Some(Error::NoMem);
                break;
            }
            let mut prot = requested;
            if read_implies_exec && requested.contains(VmaProt::READ)
                && vma.may_prot.contains(VmaProt::EXEC)
            {
                prot |= VmaProt::EXEC;
            }
            if !vma.may_prot.contains(prot)
                || self.mdwe_denies_transition(vma.prot, prot)
            {
                error = Some(Error::Access);
                break;
            }
            if let Err(security_error) = security(vma, prot) {
                error = Some(security_error);
                break;
            }
            // Linux checks MDWE before `mprotect_fixup` checks VM_SEALED.
            if vma.flags.contains(VmaFlags::SEALED) {
                error = Some(Error::Perm);
                break;
            }
            // Linux `vm_ops->may_split`: a partial mprotect of a mapping whose
            // object refuses splitting is EINVAL, decided before any fragment
            // exists.
            if (cursor > vma.start.as_u64() || end.as_u64() < vma.end.as_u64())
                && !crate::vm_ops::vma_may_split(vma)
            {
                error = Some(Error::Inval);
                break;
            }
            let step_end = vma.end.as_u64().min(end.as_u64());
            steps.push(MprotectStep {
                start: UserVirtAddr::new(cursor).expect("validated user range"),
                len: (step_end - cursor) as usize,
                prot,
                pkey: key_for(vma),
            });
            cursor = step_end;
        }

        let mut applied = 0;
        while applied < steps.len() {
            let step = steps[applied];
            let step_end = step.start.as_u64() + step.len as u64;
            let result = self.rmap_resplit(
                &mut tree, step.start.as_u64(), step_end,
                |t, s, e| t.mprotect_range_with_pkey(
                    UserVirtAddr::new(s).expect("validated user range"),
                    UserVirtAddr::new(e).expect("validated user range"),
                    step.prot,
                    Some(step.pkey),
                ),
            );
            if let Err(unexpected) = result {
                steps.truncate(applied);
                error = Some(unexpected);
                break;
            }
            for vma in tree.iter().filter(|v| {
                v.end.as_u64() > step.start.as_u64()
                    && v.start.as_u64() < step_end
            }) {
                let (name, dev, ino, pgoff) = match &vma.backing {
                    crate::VmaBacking::File { backing, off } => (
                        backing.map_path().unwrap_or(&[]), backing.dev(), backing.ino(),
                        *off / hal::PAGE_SIZE_BYTES,
                    ),
                    _ => (&[][..], 0, 0, 0),
                };
                crate::mmap_event::notify(
                    vma.start.as_u64(), vma.end.as_u64() - vma.start.as_u64(),
                    pgoff, vma.prot, vma.flags, name, dev, ino,
                );
            }
            applied += 1;
        }
        Ok(MprotectOutcome { steps, error })
    }

    /// True if any VMA in `[addr, addr+len)` is mseal'd. The syscall layer
    /// (sys_mprotect/munmap/mremap) checks this and returns EPERM when true,
    /// per mseal(2). Kernel-internal teardown (exec/exit) bypasses it — only
    /// userspace ops are sealed, matching Linux.
    /// # C: O(K)
    pub fn range_sealed(&self, addr: UserVirtAddr, len: usize) -> bool {
        match end_of_raw(addr, len as u64) {
            Ok(end) => self.vmas.read().any_sealed_raw_end(addr, end),
            Err(_)  => false,
        }
    }

    /// True if `[addr, addr+len)` would cut a VMA whose mapped object refuses
    /// to be split (Linux `vm_ops->may_split`). The syscall layer checks this
    /// and returns EINVAL; a range covering whole VMAs is never refused.
    /// # C: O(K)
    pub fn range_refuses_split(&self, addr: UserVirtAddr, len: usize) -> bool {
        match end_of_raw(addr, len as u64) {
            Ok(end) => self.vmas.read().refuses_split_raw_end(addr, end),
            Err(_)  => false,
        }
    }

    /// Whether every VMA covering `[addr, addr+len)` permits `prot` (Linux
    /// `VM_MAY*`). Used by `mprotect` to apply `personality(READ_IMPLIES_EXEC)`
    /// only where Linux's per-VMA `VM_MAYEXEC` gate would.
    /// # C: O(K)
    pub fn range_may(&self, addr: UserVirtAddr, len: usize, prot: VmaProt) -> bool {
        match end_of_raw(addr, len as u64) {
            Ok(end) => self.vmas.read().range_may_raw_end(addr, end, prot),
            Err(_)  => false,
        }
    }

    /// mseal(2): seal `[start, end)` so later userspace mprotect/munmap/
    /// mremap/MAP_FIXED/destructive-madvise fail with EPERM. `Err(Inval)` is
    /// reserved for the one condition `do_mseal` reports as ENOMEM: the range
    /// is not fully mapped. Argument validation belongs to `vmm::mseal`, which
    /// the shim has already run — passing an unvalidated range here would
    /// collapse EINVAL into ENOMEM. Idempotent; there is no unseal.
    /// # C: O(K log N)
    pub fn mseal_range(&self, start: UserVirtAddr, end: UserVirtAddr) -> KResult<()> {
        self.vmas.write().seal_range(start, end)
    }

    /// Audit hook: invariant 1 (non-overlap, `11§2`). Used by tests
    /// and by `debug-vmm` per `11§13`.
    /// # C: O(N)
    pub fn audit(&self) -> KResult<()> {
        self.vmas.read().audit_no_overlap()
    }

}
