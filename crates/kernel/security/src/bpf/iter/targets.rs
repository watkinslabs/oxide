//! The objects a BPF iterator can walk.
//!
//! One row per target this kernel can actually enumerate. A target is named
//! by a type id in the kernel's own type information, resolved through the
//! same stub-function table the LSM hooks use, so an iterator program names
//! its target exactly the way an LSM program names its hook.

extern crate alloc;
use alloc::vec::Vec;

use vfs::InodeRef;

/// Every object kind this kernel can iterate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IterTarget {
    /// Loaded programs, by ascending id.
    BpfProg,
    /// Created maps, by ascending id.
    BpfMap,
    /// Live links, by ascending id.
    BpfLink,
}

/// One target's published shape.
pub struct IterSpec {
    /// Name of the stub function an iterator program's attach target must
    /// resolve to. The name a loader knows the target by is this name
    /// without the stub prefix, so the two cannot disagree.
    pub stub: &'static str,
    /// Type names of the stub's arguments, in order: the iteration meta
    /// record, then the object each step visits.
    pub args: &'static [&'static str],
}

/// Published iterator targets, in the order the kernel's type information
/// declares their stubs.
pub const TARGETS: &[(IterTarget, IterSpec)] = &[
    (IterTarget::BpfProg, IterSpec {
        stub: "bpf_iter_bpf_prog",
        args: &["bpf_iter_meta", "bpf_prog"],
    }),
    (IterTarget::BpfMap, IterSpec {
        stub: "bpf_iter_bpf_map",
        args: &["bpf_iter_meta", "bpf_map"],
    }),
    (IterTarget::BpfLink, IterSpec {
        stub: "bpf_iter_bpf_link",
        args: &["bpf_iter_meta", "bpf_link"],
    }),
];

/// Resolve a stub function name to the target it stands for.
/// # C: O(target count)
pub fn target_by_stub_name(name: &[u8]) -> Option<IterTarget> {
    TARGETS.iter().find(|(_, spec)| spec.stub.as_bytes() == name).map(|(target, _)| *target)
}

/// Context slots an iterator program addresses: the meta record and the
/// object of the current step. Every target publishes the same two, so the
/// context shape is a property of the program type and not of the target.
pub const CONTEXT_SLOTS: usize = 2;
/// Width of one context slot.
pub const SLOT_BYTES: usize = 8;
/// Bytes of context an iterator program addresses.
pub const CONTEXT_BYTES: usize = CONTEXT_SLOTS * SLOT_BYTES;

/// Snapshot the objects one walk visits, in id order. Taken up front so the
/// walk holds no registry lock while a program runs, which is also what
/// makes the sequence a program observes internally consistent.
/// # C: O(live objects of that kind)
pub fn snapshot(target: IterTarget) -> Vec<InodeRef> {
    let mut out = Vec::new();
    let mut at = 0u32;
    while let Some(id) = next_id(target, at) {
        if let Some(object) = by_id(target, id) { out.push(object); }
        at = id;
    }
    out
}

/// Lowest live id of this kind strictly above `start`. # C: O(live objects)
fn next_id(target: IterTarget, start: u32) -> Option<u32> {
    match target {
        IterTarget::BpfProg => super::super::prog::inode::next_live_prog_id(start),
        IterTarget::BpfMap => super::super::map::inode::next_live_map_id(start),
        IterTarget::BpfLink => super::super::link::next_live_link_id(start),
    }
}

/// Resolve one object of this kind by id. # C: O(log objects)
fn by_id(target: IterTarget, id: u32) -> Option<InodeRef> {
    match target {
        IterTarget::BpfProg => super::super::prog::inode::prog_by_id(id),
        IterTarget::BpfMap => super::super::map::inode::map_by_id(id),
        IterTarget::BpfLink => super::super::link::link_by_id(id).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prefix the reference gives every iterator target's stub.
    const STUB_PREFIX: &str = "bpf_iter_";

    #[test] fn every_stub_carries_the_prefix_and_names_its_object() {
        for (_, spec) in TARGETS {
            assert!(spec.stub.starts_with(STUB_PREFIX), "{}", spec.stub);
            assert_eq!(&spec.stub[STUB_PREFIX.len()..], spec.args[1]);
        }
    }

    #[test] fn stub_names_are_unique_and_resolve_to_their_own_target() {
        for (at, (target, spec)) in TARGETS.iter().enumerate() {
            assert!(TARGETS[..at].iter().all(|(_, other)| other.stub != spec.stub));
            assert_eq!(target_by_stub_name(spec.stub.as_bytes()), Some(*target));
        }
    }

    #[test] fn an_unpublished_target_name_resolves_to_nothing() {
        for name in [&b"bpf_iter_task"[..], b"bpf_iter_bpf_map_elem", b"bpf_lsm_file_open",
            b"bpf_iter_bpf_ma", b"bpf_iter_bpf_maps", b""] {
            assert_eq!(target_by_stub_name(name), None);
        }
    }

    /// Each stub takes the meta record and the object, in that order — the
    /// two slots the context rules admit.
    #[test] fn every_target_publishes_the_two_context_arguments() {
        for (_, spec) in TARGETS {
            assert_eq!(spec.args.len(), CONTEXT_SLOTS);
            assert_eq!(spec.args[0], "bpf_iter_meta");
        }
        assert_eq!(CONTEXT_BYTES, 16);
    }
}
