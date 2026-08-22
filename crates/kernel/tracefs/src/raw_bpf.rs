// Raw-tracepoint BPF consumers of the canonical eventfs definitions.
//
// Each event owns one immutable published probe array. Attach/detach rebuild
// that array under the registration lock; emit sites clone one Arc and run it
// without the lock. The event's activation callback joins BPF users with the
// ordinary tracefs enable bit, so both consumers share one installed hook.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{LockClass, Spinlock};
use syscall::errno::Errno;
use vfs::InodeRef;

/// One security-owned program runner. Tracefs owns attachment and call-site
/// routing; it need not depend on the BPF implementation to invoke a probe.
pub type RawRunner = fn(&InodeRef, &[u64], u64);

struct RawTracepointClass;
impl LockClass for RawTracepointClass {
    fn rank() -> u16 { 98 }
    fn name() -> &'static str { "RawTracepointClass" }
}

#[derive(Clone)]
struct Probe { id: u64, prog: InodeRef, cookie: u64, run: RawRunner }

/// BPF-facing half of one static tracepoint definition. `num_args` is the
/// exact context-word count supplied by its emit site; `writable_size` is the
/// prefix a writable program may alter (zero for current built-ins).
pub struct RawEvent {
    num_args: u32,
    writable_size: u32,
    active: fn(bool),
    probes: Spinlock<Option<Arc<[Probe]>>, RawTracepointClass>,
}

impl RawEvent {
    /// Define one raw event beside its production emit site. # C: O(1)
    pub const fn new(num_args: u32, writable_size: u32, active: fn(bool)) -> Self {
        Self { num_args, writable_size, active, probes: Spinlock::new(None) }
    }

    fn attach(&self, id: u64, prog: InodeRef, cookie: u64, run: RawRunner) {
        let mut probes = self.probes.lock();
        let first = probes.as_ref().is_none_or(|p| p.is_empty());
        let mut next = probes.as_ref().map_or_else(Vec::new, |p| p.to_vec());
        next.push(Probe { id, prog, cookie, run });
        *probes = Some(Arc::from(next));
        if first { (self.active)(true); }
    }

    fn detach(&self, id: u64) {
        let mut probes = self.probes.lock();
        let Some(current) = probes.as_ref() else { return; };
        let mut next: Vec<Probe> = current.iter().filter(|p| p.id != id).cloned().collect();
        if next.len() == current.len() { return; }
        let last = next.is_empty();
        *probes = if last { None } else { Some(Arc::from(core::mem::take(&mut next))) };
        if last { (self.active)(false); }
    }

    fn fire(&self, args: &[u64]) {
        let probes = self.probes.lock().as_ref().map(Arc::clone);
        if let Some(probes) = probes {
            for probe in probes.iter() { (probe.run)(&probe.prog, args, probe.cookie); }
        }
    }
}

/// Register one program against the canonical event named by `name`.
/// # C: O(events + attached programs)
pub fn attach(
    name: &[u8],
    id: u64,
    prog: InodeRef,
    cookie: u64,
    run: RawRunner,
) -> Result<&'static str, Errno> {
    let (name, event) = crate::eventfs::raw_event_by_name(name).ok_or(Errno::Enoent)?;
    event.attach(id, prog, cookie, run);
    Ok(name)
}

/// Remove the exact probe retained by a raw-tracepoint link. # C: O(programs)
pub fn detach(name: &str, id: u64) {
    if let Some((_, event)) = crate::eventfs::raw_event_by_name(name.as_bytes()) {
        event.detach(id);
    }
}

/// Run every probe attached to one event. # C: O(programs × instructions)
pub(crate) fn fire(event: &RawEvent, args: &[u64]) {
    debug_assert_eq!(args.len(), event.num_args as usize);
    let _ = event.writable_size;
    event.fire(args);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    static SEEN_NR: AtomicU64 = AtomicU64::new(0);
    static SEEN_COOKIE: AtomicU64 = AtomicU64::new(0);

    fn observe(_: &InodeRef, args: &[u64], cookie: u64) {
        SEEN_NR.store(args[1], Ordering::Release);
        SEEN_COOKIE.store(cookie, Ordering::Release);
    }

    #[test]
    fn canonical_sys_enter_hook_runs_and_detaches_the_raw_program() {
        const ID: u64 = 0xb2334;
        const COOKIE: u64 = 0xc001_cafe;
        let prog = vfs::StaticFileInode::new(b"raw-program");
        let name = attach(b"sys_enter", ID, prog, COOKIE, observe).unwrap();
        assert_eq!(name, "sys_enter");

        SEEN_NR.store(0, Ordering::Release);
        SEEN_COOKIE.store(0, Ordering::Release);
        let args = syscall::SyscallArgs { a0: 1, a1: 2, a2: 3, a3: 4, a4: 5, a5: 6 };
        syscall::tracepoint::fire_sys_enter(321, &args);
        assert_eq!(SEEN_NR.load(Ordering::Acquire), 321);
        assert_eq!(SEEN_COOKIE.load(Ordering::Acquire), COOKIE);

        detach(name, ID);
        SEEN_NR.store(0, Ordering::Release);
        syscall::tracepoint::fire_sys_enter(322, &args);
        assert_eq!(SEEN_NR.load(Ordering::Acquire), 0,
                   "final link close removes the production-hook probe");
    }
}
