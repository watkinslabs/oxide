//! Typed handoff from a validated PE image to the NT personality.

use hal::UserVirtAddr;
use pe::Error;
use vmm::{AddressSpace, VmaBacking, VmaProt};

/// Immutable facts carried by the first NT user context.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeStartupFacts {
    pub image_entry: UserVirtAddr,
    pub transfer_entry: UserVirtAddr,
    pub stack_pointer: UserVirtAddr,
    pub gs_base: UserVirtAddr,
    pub peb: UserVirtAddr,
    pub teb: UserVirtAddr,
    pub personality: super::pe_loader::ExecutionPersonality,
}

/// A validated, single-use boundary between image construction and task
/// publication. No caller can obtain startup facts until all address-space
/// and x64 entry-state checks have succeeded.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeStartupTransaction { facts: PeStartupFacts }

impl PeStartupTransaction {
    /// Validate the PE transfer address, NT environment pointers, and Windows
    /// x64 stack contract against the address space that owns them.
    /// # C: O(1)
    pub fn begin(as_: &AddressSpace, image: &super::pe_loader::PeLoadedImage,
        env: &super::process_env::NtProcessEnvironment, stack_base: u64,
        stack_top: u64, state: &super::pe_loader::PeEntryState,
        initializer: Option<&super::pe_init::PeInitTrampoline>) -> Result<Self, Error> {
        if state.personality != super::pe_loader::ExecutionPersonality::Nt
            || !executable(as_, image.entry) || !executable(as_, state.rip)
            || (initializer.map_or(state.rip != image.entry, |value| state.rip != value.entry))
            || state.gs_base != env.teb { return Err(Error::Einval); }
        if stack_base != 0 {
            if stack_base >= stack_top { return Err(Error::Einval); }
            let top = UserVirtAddr::new(stack_top.checked_sub(1).ok_or(Error::Einval)?).ok_or(Error::Einval)?;
            let vma = as_.find_vma(top).ok_or(Error::Einval)?;
            let rsp = state.rsp.as_u64();
            if vma.start.as_u64() != stack_base || vma.end.as_u64() != stack_top
                || !vma.prot.contains(VmaProt::READ | VmaProt::WRITE)
                || !matches!(vma.backing, VmaBacking::Anonymous)
                || rsp < stack_base
                || rsp.checked_add(super::process_env::X64_SHADOW_SPACE + super::process_env::X64_RETURN_SLOT).ok_or(Error::Einval)? > stack_top { return Err(Error::Einval); }
        }
        let env_end = env.base.as_u64().checked_add(env.bytes as u64).ok_or(Error::Einval)?;
        if env.bytes == 0 || env.base.as_u64() >= env_end { return Err(Error::Einval); }
        for address in [env.peb.as_u64(), env.teb.as_u64()] {
            if address < env.base.as_u64() || address >= env_end
                || UserVirtAddr::new(address).and_then(|value| as_.find_vma(value)).is_none() { return Err(Error::Einval); }
        }
        Ok(Self { facts: PeStartupFacts {
            image_entry: image.entry, transfer_entry: state.rip, stack_pointer: state.rsp,
            gs_base: state.gs_base, peb: env.peb, teb: env.teb, personality: state.personality,
        } })
    }

    /// Consume the transaction and expose the immutable startup facts to the
    /// NT exec commit. # C: O(1)
    pub fn finish(self) -> PeStartupFacts { self.facts }
}

fn executable(as_: &AddressSpace, address: UserVirtAddr) -> bool {
    as_.find_vma(address).is_some_and(|vma| vma.prot.contains(VmaProt::EXEC))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_facts_are_immutable_and_distinguish_image_from_transfer() {
        let facts = PeStartupFacts {
            image_entry: UserVirtAddr::new(0x1400_1010).unwrap(),
            transfer_entry: UserVirtAddr::new(0x7000_0000).unwrap(),
            stack_pointer: UserVirtAddr::new(0x6000_0fd8).unwrap(),
            gs_base: UserVirtAddr::new(0x5000_0100).unwrap(),
            peb: UserVirtAddr::new(0x5000_0000).unwrap(),
            teb: UserVirtAddr::new(0x5000_0100).unwrap(),
            personality: super::super::pe_loader::ExecutionPersonality::Nt,
        };
        assert_ne!(facts.image_entry, facts.transfer_entry);
        assert_eq!(facts.personality, super::super::pe_loader::ExecutionPersonality::Nt);
    }
}
