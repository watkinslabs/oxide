// futex2 NUMA/memory-policy key preflight: the user-memory half of the node
// ladder. Every decision belongs to `crate::futex_numa`; this file only reads
// the node-id word, asks the address space for the mapping's memory policy,
// and publishes the resolved node back. Kernel-gated, so it holds no rule a
// test could not reach.

use syscall::errno::Errno;

use crate::futex2_flags::Futex2Flags;
use crate::futex_numa::{addr_aligned, mpol_node, node_word_addr, resolve_node};

/// Memory policy attached to the mapping holding `uaddr`, or `None` when the
/// address has no mapping. An unmapped address is not an error here: the futex
/// word itself is accessed separately and reports `EFAULT` on its own.
/// # C: O(log N)
fn policy_at(uaddr: u64) -> Option<vmm::mempolicy::MemPolicy> {
    let cur = sched::live::current()?;
    // SAFETY: mm slot single-mutator per `13§5` — `cur` is this CPU's running
    // task and only its own execve/exit may replace the slot.
    let mm = unsafe { cur.mm_ref() }?;
    // The policy is looked up at the page the futex lives on, matching the
    // page-aligned address the key is built from.
    mm.vma_policy_at(uaddr & !(hal::PAGE_SIZE_BYTES - 1)).ok().flatten()
}

/// Resolve and publish the node a futex2 operand is keyed on, before the
/// operation touches the futex word.
///
/// Runs the whole operand contract in the reference's order: natural alignment
/// of the (possibly doubled) operand, then the node-id word, then the memory
/// policy, then the running node, then the write-back. Alignment outranks
/// accessibility — an unaligned address is `EINVAL` whatever is mapped there.
/// # C: O(log N) worst case via the policy lookup
pub fn futex2_key_preflight(uaddr: u64, f: &Futex2Flags) -> Result<(), Errno> {
    let access = f.access_bytes();
    if !addr_aligned(uaddr, access) { return Err(Errno::Einval); }
    if uaddr == 0 || uaddr.saturating_add(access as u64) > hal::USER_VA_END {
        return Err(Errno::Efault);
    }
    if !f.numa && !f.mpol { return Ok(()); }
    let naddr = node_word_addr(uaddr, access);
    let user_node = if f.numa { Some(crate::useraccess::read_i32(naddr)?) } else { None };
    // The policy is consulted only when it can still decide the node; skipping
    // it otherwise keeps a caller that already named its node off the VMA tree.
    let needs_policy = f.mpol && user_node.unwrap_or(crate::futex_numa::FUTEX_NO_NODE)
        == crate::futex_numa::FUTEX_NO_NODE;
    let policy_node = if needs_policy { mpol_node(policy_at(uaddr)) }
                      else { crate::futex_numa::FUTEX_NO_NODE };
    let out = resolve_node(f.numa, f.mpol, user_node, policy_node)
        .map_err(|_| Errno::Einval)?;
    if let Some(node) = out.write_back { crate::useraccess::write_u32(naddr, node as u32)?; }
    Ok(())
}
