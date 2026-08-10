// The program installed on a reuseport group, with the map set it may name a
// member through.
//
// A classic filter answers with a member index and reaches no maps at all. A
// selection program answers with an action and names its member through a
// socket-holding map, so it needs the relocated map set its instructions index
// into carried alongside the instructions themselves — without it the load-time
// relocation would resolve to nothing and every selection call would fail.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use security::bpf::map::sockarray::SockHandle;

use crate::bpf_filter::FilterProgram;

/// One installed program and the maps it may reach.
pub struct GroupProgram {
    pub program: FilterProgram,
    /// Index order matches the relocation the loader performed; empty for a
    /// program that names no map.
    pub maps: Vec<vfs::InodeRef>,
}

impl GroupProgram {
    /// A program that reaches no maps: every classic filter, and any selection
    /// program that only ever drops or defers. # C: O(1)
    pub fn bare(program: FilterProgram) -> Self { Self { program, maps: Vec::new() } }
}

/// Where a named socket sits among the candidates a delivery path is choosing
/// between. A handle naming an object of a different shape, or one that is not
/// a candidate here, places nowhere, and the caller falls back to its own
/// distribution rather than dropping a packet that still belongs to the key.
/// # C: O(candidates)
pub fn member_index<T>(handle: &SockHandle, candidates: &[Arc<T>]) -> Option<usize>
    where T: Any + Send + Sync
{
    let named = handle.upgrade()?.downcast::<T>().ok()?;
    candidates.iter().position(|candidate| Arc::ptr_eq(candidate, &named))
}
