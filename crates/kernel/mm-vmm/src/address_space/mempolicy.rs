// AddressSpace half of the mempolicy syscalls: the VMA-policy writers and
// readers `mbind(2)`, `get_mempolicy(MPOL_F_ADDR)` and
// `set_mempolicy_home_node(2)` drive.

use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::mempolicy::MemPolicy;
use crate::tree::HomeNodeErr;

impl AddressSpace {
    /// `mbind_range` over `[start, end)`, splitting VMAs at the boundaries.
    /// The caller has already run `queue_pages_range`, which owns the hole
    /// (`EFAULT`) and `MPOL_MF_STRICT` (`EIO`) decisions.
    /// # C: O(K log N)
    pub fn set_policy_range(&self, start: u64, end: u64, pol: Option<MemPolicy>) {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end)) else { return };
        self.vmas.write().set_policy_range(s, e, pol);
    }

    /// `set_mempolicy_home_node`'s VMA walk. `Err(NoEnt)` when no VMA in the
    /// range carried a policy — Linux's `err = -ENOENT` initial value, which
    /// survives untouched when every VMA is skipped.
    /// # C: O(K log N)
    pub fn set_home_node_range(&self, start: u64, end: u64, home_node: i32)
        -> Result<(), HomeNodeErr>
    {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end))
            else { return Err(HomeNodeErr::NoEnt) };
        self.vmas.write().set_home_node_range(s, e, home_node)
    }

    /// `__get_vma_policy(vma_lookup(mm, addr))`. `Ok(None)` is a mapped
    /// address with no VMA policy, which `get_mempolicy` reports as
    /// `MPOL_DEFAULT`; `Err(())` is "no VMA there", which is `EFAULT`.
    /// # C: O(log N)
    pub fn vma_policy_at(&self, addr: u64) -> Result<Option<MemPolicy>, ()> {
        let uva = UserVirtAddr::new(addr).ok_or(())?;
        let tree = self.vmas.read();
        match tree.find_containing(uva) { Some(v) => Ok(v.mempolicy), None => Err(()) }
    }

    /// Whether a page pinned on this task's own behalf at `addr` may be read.
    /// `check_vma_flags` refuses a range without `VM_READ`, and then refuses
    /// one whose protection key denies this thread — a pin has no hardware
    /// check of its own, so the key must be tested here or not at all.
    ///
    /// `allows` decodes the caller's live rights register; the register's bit
    /// layout stays owned by the arch that defines it.
    /// # C: O(log N)
    pub fn gup_read_permitted(&self, addr: u64, allows: impl FnOnce(u8, bool, bool) -> bool) -> bool {
        let Some(uva) = UserVirtAddr::new(addr) else { return false };
        let tree = self.vmas.read();
        let Some(v) = tree.find_containing(uva) else { return false };
        if !v.prot.contains(crate::vma::VmaProt::READ) { return false; }
        // A secret-memory page has no kernel-visible address at all, so it can
        // never be pinned for anyone.
        if v.flags.contains(crate::vma::VmaFlags::SECRETMEM) { return false; }
        // A pin is a data access issued for this mm, never an instruction
        // fetch and never foreign.
        super::pkeys::vma_access_permitted(&self.pkeys.arch(), v.pkey, false, false, false, allows)
    }
}
