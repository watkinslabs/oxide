// Per-task io_uring registered-ring array — Linux `io_uring_task.registered_rings`.
//
// A ring descriptor registered here is addressed by a small INDEX instead of an
// fd, which is what lets `io_uring_enter` skip the fd-table lookup on every
// submission. The array is per-TASK, not per-ring and not per-process: the
// reference hangs it off the task that registered, and drops every slot both at
// exit and at `execve`, because a new image inherits no ring registrations.
//
// The array lives here rather than beside the ring code because `Task` is the
// only thing whose lifetime it can follow. The ring layer owns what a slot MAY
// hold (it alone can tell an io_uring descriptor from any other file); this
// module owns the slots, their bounds and their teardown.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::File;

use super::Task;

/// `IO_RINGFD_REG_MAX`: how many rings one task may register.
pub const IO_RINGFD_REG_MAX: usize = 16;

/// The register form's "pick any free slot" offset (`-1U`).
pub const IO_RINGFD_ALLOC_ANY: u32 = u32::MAX;

/// The registered-ring slot array itself. Allocated on first registration.
pub type RegisteredRings = [Option<Arc<File>>; IO_RINGFD_REG_MAX];

/// A fresh, empty slot array. # C: O(IO_RINGFD_REG_MAX)
fn empty_rings() -> Box<RegisteredRings> { Box::new([const { None }; IO_RINGFD_REG_MAX]) }

/// Bounds-check an offset against the array. # C: O(1)
fn slot_index(offset: u32) -> Result<usize, Errno> {
    let idx = usize::try_from(offset).map_err(|_| Errno::Einval)?;
    if idx >= IO_RINGFD_REG_MAX { return Err(Errno::Einval); }
    Ok(idx)
}

impl Task {
    /// Install `file` at `offset`, or at the first free slot when `offset` is
    /// [`IO_RINGFD_ALLOC_ANY`]. Returns the slot actually used, which the
    /// caller writes back to the registration record.
    ///
    /// `EINVAL` for an out-of-range explicit offset, `EBUSY` when the named
    /// slot is taken or when an any-slot request finds the array full.
    /// # C: O(IO_RINGFD_REG_MAX)
    pub fn io_uring_ring_install(&self, offset: u32, file: Arc<File>) -> Result<u32, Errno> {
        // Bounds first: an out-of-range request must not be what allocates the
        // context for a task that has registered nothing.
        let explicit = if offset == IO_RINGFD_ALLOC_ANY { None } else { Some(slot_index(offset)?) };
        let mut ctx = self.registered_rings.lock();
        let slots = ctx.get_or_insert_with(empty_rings);
        match explicit {
            // An explicit offset collapses the search to one slot, so an
            // occupied slot is the same "nothing free" answer the any-slot
            // form gives.
            Some(idx) if slots[idx].is_some() => Err(Errno::Ebusy),
            Some(idx) => { slots[idx] = Some(file); Ok(idx as u32) }
            None => {
                let free = slots.iter().position(Option::is_none).ok_or(Errno::Ebusy)?;
                slots[free] = Some(file);
                Ok(free as u32)
            }
        }
    }

    /// Clear slot `offset`. Reports whether a registration was actually
    /// removed: clearing an already-empty slot is NOT an error in the
    /// reference, so an unregister sweep over a sparse array succeeds.
    /// # C: O(1)
    pub fn io_uring_ring_remove(&self, offset: u32) -> Result<bool, Errno> {
        let idx = slot_index(offset)?;
        // Dropped after the lock: closing a ring file runs its release path.
        let taken = self.registered_rings.lock().as_mut().and_then(|s| s[idx].take());
        Ok(taken.is_some())
    }

    /// Resolve a registered-ring index to its file.
    ///
    /// `EINVAL` past the end of the array, `EBADF` for an empty in-range slot —
    /// the same split the reference draws between "no such slot" and "that slot
    /// names no descriptor".
    /// # C: O(1)
    pub fn io_uring_ring_lookup(&self, offset: u32) -> Result<Arc<File>, Errno> {
        let idx = slot_index(offset)?;
        self.registered_rings.lock().as_ref().and_then(|s| s[idx].clone()).ok_or(Errno::Ebadf)
    }

    /// How many slots currently hold a registration. # C: O(IO_RINGFD_REG_MAX)
    pub fn io_uring_rings_registered(&self) -> usize {
        self.registered_rings.lock().as_ref()
            .map_or(0, |s| s.iter().filter(|e| e.is_some()).count())
    }

    /// Drop every registration. Runs at task exit and at `execve`, because a
    /// task that has replaced its image holds no ring the old one registered.
    /// # C: O(1) + file releases
    pub fn io_uring_rings_drain(&self) {
        let taken = self.registered_rings.lock().take();
        // The releases run with the slot lock dropped: a ring's release path
        // can block and can look at this very task.
        drop(taken);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::SchedClass;
    use vfs::OpenFlags;

    fn task(tid: u32) -> Task { Task::new(tid, "t", SchedClass::Normal { weight: 1024 }) }

    /// A file standing in for a ring descriptor. What makes a slot legal is
    /// decided by the ring layer; the array only cares that it holds one file.
    fn ring(ino: u64) -> Arc<File> {
        let inode = vfs::InodeBuilder::new(ino, vfs::S_IFCHR | 0o600,
            Arc::new(vfs::DefaultInodeOps), Arc::new(vfs::DefaultFileOps)).build();
        let d = vfs::Dentry::new(None, alloc::string::String::from("ring"), inode.clone());
        File::new(inode, d, OpenFlags::empty())
    }

    #[test]
    fn an_explicit_offset_takes_exactly_that_slot() {
        let t = task(8001);
        assert_eq!(t.io_uring_ring_install(3, ring(1)).expect("free slot"), 3);
        assert_eq!(t.io_uring_rings_registered(), 1);
        assert!(t.io_uring_ring_lookup(3).is_ok());
        assert_eq!(t.io_uring_ring_lookup(4).err(), Some(Errno::Ebadf),
            "an in-range empty slot names no descriptor");
    }

    #[test]
    fn a_task_that_registers_nothing_allocates_no_context() {
        // The reference allocates its per-task io_uring context on first use;
        // most tasks never open a ring and must not pay for the slots.
        let t = task(8007);
        assert!(t.registered_rings.lock().is_none());
        assert_eq!(t.io_uring_rings_registered(), 0);
        assert_eq!(t.io_uring_ring_remove(0), Ok(false));
        assert_eq!(t.io_uring_ring_lookup(0).err(), Some(Errno::Ebadf));
        assert!(t.registered_rings.lock().is_none(),
            "a query must not be what allocates the context");
    }

    #[test]
    fn an_offset_past_the_array_is_an_argument_error_not_a_bad_descriptor() {
        let t = task(8002);
        assert_eq!(t.io_uring_ring_install(IO_RINGFD_REG_MAX as u32, ring(1)).err(), Some(Errno::Einval));
        assert_eq!(t.io_uring_ring_lookup(IO_RINGFD_REG_MAX as u32).err(), Some(Errno::Einval));
        assert_eq!(t.io_uring_ring_remove(IO_RINGFD_REG_MAX as u32), Err(Errno::Einval));
        assert!(t.registered_rings.lock().is_none(),
            "an out-of-range request must not allocate the context");
    }

    #[test]
    fn an_occupied_slot_reports_busy_rather_than_replacing_its_registration() {
        let t = task(8003);
        let first = ring(1);
        t.io_uring_ring_install(0, Arc::clone(&first)).expect("free slot");
        assert_eq!(t.io_uring_ring_install(0, ring(2)).err(), Some(Errno::Ebusy));
        assert!(Arc::ptr_eq(&t.io_uring_ring_lookup(0).expect("still there"), &first),
            "a refused registration must not have displaced the live one");
    }

    #[test]
    fn the_any_slot_form_fills_holes_in_order_and_reports_busy_when_full() {
        let t = task(8004);
        for i in 0..IO_RINGFD_REG_MAX {
            assert_eq!(t.io_uring_ring_install(IO_RINGFD_ALLOC_ANY, ring(i as u64)).expect("free"),
                       i as u32, "the any-slot form must fill from the low end");
        }
        assert_eq!(t.io_uring_ring_install(IO_RINGFD_ALLOC_ANY, ring(99)).err(), Some(Errno::Ebusy));
        assert!(t.io_uring_ring_remove(5).expect("in range"));
        assert_eq!(t.io_uring_ring_install(IO_RINGFD_ALLOC_ANY, ring(99)).expect("hole"), 5);
    }

    #[test]
    fn clearing_an_empty_slot_succeeds_without_removing_anything() {
        // The reference's unregister sweep walks a sparse array and must not
        // fail on the holes in it.
        let t = task(8005);
        assert_eq!(t.io_uring_ring_remove(7), Ok(false));
        t.io_uring_ring_install(7, ring(1)).expect("free slot");
        assert_eq!(t.io_uring_ring_remove(7), Ok(true));
        assert_eq!(t.io_uring_ring_remove(7), Ok(false));
    }

    #[test]
    fn teardown_drops_every_registration_and_its_file_reference() {
        let t = task(8006);
        let held = ring(1);
        t.io_uring_ring_install(2, Arc::clone(&held)).expect("free slot");
        t.io_uring_ring_install(9, Arc::clone(&held)).expect("free slot");
        assert_eq!(Arc::strong_count(&held), 3);
        t.io_uring_rings_drain();
        assert_eq!(t.io_uring_rings_registered(), 0);
        assert_eq!(Arc::strong_count(&held), 1,
            "exit must release the ring files, not merely forget the slots");
    }
}
