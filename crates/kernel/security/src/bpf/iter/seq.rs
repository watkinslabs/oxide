//! The descriptor `BPF_ITER_CREATE` mints: one walk of an iterator link's
//! target, driven by reads.
//!
//! A read runs the link's program once per live object of the target, in id
//! order, and once more with no object to mark the end of the walk — the
//! sequence a reader observes is therefore the same sequence the program
//! observed. Bytes the program emitted are what the read returns; this
//! kernel has no emitting helper yet, so a walk that runs to completion
//! reports end of file.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::{FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_inode_ops,
          mk_mode, FileOps};

use super::super::{BPF_FD_MODE, ids, install_fd_access};
use super::BpfIterLinkInode;
use super::targets::{self, CONTEXT_BYTES, SLOT_BYTES};

/// Iteration meta record handed to the program as its first context slot.
/// The program may observe the slot and may not follow it, so the record's
/// only role is to be a live identity that changes per step. It carries the
/// step number and nothing else: the reference's session id and seq handle
/// become observable only once a helper can read through this pointer.
struct IterMeta {
    seq_num: u64,
}

/// One `BPF_ITER_CREATE` descriptor.
pub struct BpfIterSeqInode {
    /// Pins the link, and through it the program and its target.
    link: InodeRef,
    state: Spinlock<SeqState, TaskListClass>,
}

#[derive(Default)]
struct SeqState {
    /// Bytes the completed walk produced; `None` until the first read runs
    /// the walk.
    produced: Option<Vec<u8>>,
}

/// What one program run asked the walk to do.
enum Step {
    /// Move on to the next object.
    Next,
    /// Show this object again. Nothing about a second attempt differs here
    /// — the emitted bytes have no size limit to relieve — so the request
    /// cannot be satisfied and the reader is told so.
    Retry,
    /// The program could not be run at all.
    Failed,
}

/// Judge one program return. # C: O(1)
fn step(answer: Option<i64>) -> Step {
    match answer {
        Some(0) => Step::Next,
        Some(_) => Step::Retry,
        None => Step::Failed,
    }
}

/// Run one iterator program over `object`, or over the end of the walk when
/// `object` is `None`. # C: O(instructions run)
fn run_step(prog: &InodeRef, meta: &IterMeta, object: Option<&InodeRef>) -> Step {
    let mut context = [0u8; CONTEXT_BYTES];
    let meta_slot = meta as *const IterMeta as usize as u64;
    let object_slot = object.map(|o| Arc::as_ptr(o) as *const u8 as usize as u64).unwrap_or(0);
    context[..SLOT_BYTES].copy_from_slice(&meta_slot.to_ne_bytes());
    context[SLOT_BYTES..].copy_from_slice(&object_slot.to_ne_bytes());
    let mut helper_state = crate::bpf_interp::HelperState::default();
    let answer = prog.private::<super::super::BpfProgInode>().and_then(|loaded| {
        crate::bpf_interp::run_program_with_state(&loaded, &context, &[], &[], &mut helper_state)
    });
    step(answer)
}

impl BpfIterSeqInode {
    /// Run the whole walk once, in id order, ending with the no-object step.
    /// # C: O(live objects × instructions run)
    fn walk(&self) -> Result<Vec<u8>, Errno> {
        let link = self.link.private::<BpfIterLinkInode>().ok_or(Errno::Einval)?;
        let prog = link.prog();
        let objects = targets::snapshot(link.target());
        let mut meta = IterMeta { seq_num: 0 };
        for object in objects.iter() {
            match run_step(&prog, &meta, Some(object)) {
                Step::Next => meta.seq_num += 1,
                Step::Retry => return Err(Errno::Eagain),
                Step::Failed => return Err(Errno::Einval),
            }
        }
        match run_step(&prog, &meta, None) {
            Step::Next => Ok(Vec::new()),
            Step::Retry => Err(Errno::Eagain),
            Step::Failed => Err(Errno::Einval),
        }
    }

    /// Bytes of the completed walk, running it on first read. # C: O(walk)
    fn produced(&self) -> Result<Vec<u8>, Errno> {
        if let Some(done) = self.state.lock().produced.as_ref() { return Ok(done.clone()); }
        let done = self.walk()?;
        self.state.lock().produced = Some(done.clone());
        Ok(done)
    }
}

struct IterSeqOps;

impl FileOps for IterSeqOps {
    /// # C: O(walk) on the first read, O(n) after
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let seq = inode.private::<BpfIterSeqInode>().ok_or(VfsError::Einval)?;
        let done = seq.produced().map_err(errno_to_vfs)?;
        let Ok(off) = usize::try_from(off) else { return Ok(0) };
        if off >= done.len() { return Ok(0); }
        let n = (done.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&done[off..off + n]);
        Ok(n)
    }
}

/// The two failures a walk can report, as the reader sees them. # C: O(1)
fn errno_to_vfs(errno: Errno) -> VfsError {
    match errno {
        Errno::Eagain => VfsError::Eagain,
        _ => VfsError::Einval,
    }
}

/// `bpf_iter_new_fd()`: a read-only descriptor over one walk of the link's
/// target. # C: O(fd words)
pub(super) fn new_fd(link: InodeRef) -> Result<i64, Errno> {
    let seq = BpfIterSeqInode { link, state: Spinlock::new(SeqState::default()) };
    let inode = InodeBuilder::new(ids::INO_ITER, mk_mode(FileType::Regular, BPF_FD_MODE),
        default_inode_ops(), Arc::new(IterSeqOps))
        .private(Arc::new(seq))
        .build();
    install_fd_access(inode, "bpf_iter", vfs::OpenFlags::O_RDONLY)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program that runs and returns zero advances the walk; anything
    /// else it returns asks for a repeat the walk cannot grant; a program
    /// that will not run at all is neither.
    #[test] fn the_step_verdict_separates_advance_repeat_and_failure() {
        assert!(matches!(step(Some(0)), Step::Next));
        assert!(matches!(step(Some(1)), Step::Retry));
        assert!(matches!(step(Some(-1)), Step::Retry));
        assert!(matches!(step(None), Step::Failed));
    }

    /// The two walk failures reach the reader as different answers.
    #[test] fn a_repeat_request_and_a_dead_program_are_different_errors() {
        assert_eq!(errno_to_vfs(Errno::Eagain), VfsError::Eagain);
        assert_eq!(errno_to_vfs(Errno::Einval), VfsError::Einval);
        assert_ne!(VfsError::Eagain, VfsError::Einval);
    }
}
