// Linux Memory-Deny-Write-Execute state and policy.
//
// MDWE is an `mm_struct` property: CLONE_VM threads share it, while fork and
// exec construct a new address space with `MMF_INIT_LEGACY_MASK` inheritance.
// Keeping both the state transition and VMA admission policy here prevents the
// prctl, mmap, mprotect, and shmat call sites from growing separate truths.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::vma::VmaProt;
use crate::{Error, KResult};

use super::AddressSpace;

/// One fully validated `PR_SET_MDWE` request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdweRequest {
    Disabled,
    RefuseExecGain,
    RefuseExecGainNoInherit,
}

/// `PR_SET_MDWE` may never change a non-zero request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MdweSetError {
    Immutable,
}

/// Proof that the canonical mm owner admitted one new mapping.
///
/// PMM consumes this after its MAP_FIXED page-table teardown, avoiding a
/// second policy decision which could fail after the old mapping was removed.
/// Private fields make the proof unforgeable outside VMM.
pub struct MdweAdmission {
    owner: usize,
    prot: VmaProt,
}

pub(super) struct MdweState(AtomicU8);

impl MdweState {
    const DISABLED: u8 = 0;
    const REFUSE: u8 = 1;
    const REFUSE_NO_INHERIT: u8 = 2;

    pub(super) const fn new() -> Self { Self(AtomicU8::new(Self::DISABLED)) }

    const fn encode(request: MdweRequest) -> u8 {
        match request {
            MdweRequest::Disabled => Self::DISABLED,
            MdweRequest::RefuseExecGain => Self::REFUSE,
            MdweRequest::RefuseExecGainNoInherit => Self::REFUSE_NO_INHERIT,
        }
    }

    pub(super) fn inherited_from(parent: &Self) -> Self {
        let inherited = match parent.get() {
            MdweRequest::RefuseExecGainNoInherit => MdweRequest::Disabled,
            state => state,
        };
        Self(AtomicU8::new(Self::encode(inherited)))
    }

    fn inherit_from(&self, parent: &Self) {
        let inherited = Self::inherited_from(parent).get();
        self.0.store(Self::encode(inherited), Ordering::Release);
    }

    fn get(&self) -> MdweRequest {
        match self.0.load(Ordering::Acquire) {
            Self::REFUSE => MdweRequest::RefuseExecGain,
            Self::REFUSE_NO_INHERIT => MdweRequest::RefuseExecGainNoInherit,
            _ => MdweRequest::Disabled,
        }
    }

    fn set(&self, request: MdweRequest) -> Result<(), MdweSetError> {
        loop {
            let current = self.0.load(Ordering::Acquire);
            let requested = Self::encode(request);
            if current != Self::DISABLED {
                return if current == requested {
                    Ok(())
                } else {
                    Err(MdweSetError::Immutable)
                };
            }
            match self.0.compare_exchange(
                current,
                requested,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }

    fn denies(&self, old: VmaProt, new: VmaProt) -> bool {
        if self.get() == MdweRequest::Disabled || !new.contains(VmaProt::EXEC) {
            return false;
        }
        new.contains(VmaProt::WRITE) || !old.contains(VmaProt::EXEC)
    }
}

impl MdweAdmission {
    pub(super) fn validate(self, owner: &AddressSpace, prot: VmaProt) -> KResult<()> {
        if self.owner != owner as *const AddressSpace as usize || self.prot != prot {
            return Err(Error::Inval);
        }
        Ok(())
    }
}

impl AddressSpace {
    /// Construct an exec address space with Linux MDWE inheritance applied
    /// before the first stack or ELF VMA is installed. # C: O(1)
    pub fn new_for_exec(root_pa: u64, parent: &Self) -> KResult<alloc::sync::Arc<Self>> {
        let child = Self::new(root_pa)?;
        child.mdwe.inherit_from(&parent.mdwe);
        Ok(child)
    }

    /// Current `PR_GET_MDWE` value. # C: O(1)
    pub fn mdwe_get(&self) -> MdweRequest { self.mdwe.get() }

    /// Apply Linux's immutable-after-enable `PR_SET_MDWE` transition. # C: O(1)
    pub fn mdwe_set(&self, request: MdweRequest) -> Result<(), MdweSetError> {
        self.mdwe.set(request)
    }

    /// Admit one new VMA using Linux `map_deny_write_exec(new, new)`.
    /// The returned proof is consumed by MAP_FIXED after PMM teardown.
    /// # C: O(1)
    pub fn mdwe_admit_new_mapping(&self, prot: VmaProt) -> KResult<MdweAdmission> {
        if self.mdwe.denies(prot, prot) { return Err(Error::Access); }
        Ok(MdweAdmission { owner: self as *const Self as usize, prot })
    }

    pub(super) fn mdwe_denies_transition(&self, old: VmaProt, new: VmaProt) -> bool {
        self.mdwe.denies(old, new)
    }
}
