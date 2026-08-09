// The ABI-shim half of perf's side-band records: gather what the reference's
// `perf_event_mmap`/`_comm`/`_fork`/`_exit` read off `current` and the vma, and
// hand it to the `fs::perf::sideband` work fn. No policy here — which events
// want a record, and its byte layout, both live in the owning subsystem.

use fs::perf::sideband::{self, MmapInfo};

/// `PROT_READ`/`PROT_WRITE`/`PROT_EXEC`. `PROT_EXEC` is what selects
/// `attr.mmap` events over `attr.mmap_data` ones.
const PROT_READ:  u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC:  u64 = 4;

/// `MAP_PRIVATE` — every mapping the ELF loader installs is private, which is
/// what the record's `flags` field reports.
const MAP_PRIVATE: u64 = 2;

/// The loader speaks `VmaProt`; the record carries the `PROT_*` bits a
/// consumer reads. Kept separate from the emit loop because a mistranslation
/// here silently reclassifies a code mapping as data, and the record then goes
/// to the wrong events entirely.
/// # C: O(1)
pub fn prot_bits(p: vmm::VmaProt) -> u64 {
    let mut out = 0;
    if p.contains(vmm::VmaProt::READ)  { out |= PROT_READ; }
    if p.contains(vmm::VmaProt::WRITE) { out |= PROT_WRITE; }
    if p.contains(vmm::VmaProt::EXEC)  { out |= PROT_EXEC; }
    out
}

/// `perf_event_mmap(vma)` for every mapping an `execve` installed.
///
/// The reference gets these for free: `elf_map()` goes through `do_mmap()`, so
/// a PT_LOAD is reported by the same VMA-layer code that reports an `mmap(2)`.
/// oxide's emitter sits above the VMA layer, so the loader hands back what it
/// mapped and this runs the same records over it.
///
/// Without it a sample taken in the main executable — the common case for
/// `PERF_SAMPLE_IP` — names no object at all, because the binary's own
/// segments never went through `mmap(2)`. The interpreter's DSOs always did.
/// # C: O(mappings × events)
pub fn note_exec_mappings(maps: &[elf_load::ImageMapping]) {
    for m in maps {
        let (name, ino) = match m.file.as_ref() {
            Some(f) => (f.map_path().unwrap_or(&[]), f.ino()),
            None    => (&[][..], 0),
        };
        note_mmap(m.addr, m.len, m.pgoff, prot_bits(m.prot), MAP_PRIVATE, name, m.dev, ino);
    }
}

/// Who the record is about and which CPU it is attributed to.
fn who() -> Option<(u32, i32)> {
    let cur = sched::live::current()?;
    Some((cur.tid, cur.cpu.load(core::sync::atomic::Ordering::Relaxed) as i32))
}

/// `perf_event_mmap(vma)` after a successful `mmap(2)`.
///
/// `dev`/`ino` identify the mapped file so a consumer can match the record
/// against the object it opens; an anonymous mapping reports zeros and an empty
/// name, exactly as the reference's `//anon` path does before it substitutes a
/// synthetic name.
/// # C: O(events × name)
pub fn note_mmap(addr: u64, len: u64, pgoff: u64, prot: u64, flags: u64,
                 name: &[u8], dev: u64, ino: u64)
{
    let Some((tid, cpu)) = who() else { return };
    sideband::mmap(tid, cpu, &MmapInfo {
        pid: 0, tid, addr, len, pgoff,
        // `st_dev` splits into the record's `maj`/`min` the same way
        // `MAJOR()`/`MINOR()` do.
        maj: (dev >> 8) as u32, min: (dev & 0xff) as u32,
        ino, ino_generation: 0,
        prot: prot as u32, flags: flags as u32,
        executable: prot & PROT_EXEC != 0,
        name,
    });
}

/// `perf_event_fork(child)`. # C: O(events)
pub fn note_fork(child_tid: u32, child_pid: u32, parent_tid: u32, parent_pid: u32) {
    let cpu = who().map_or(0, |(_, c)| c);
    sideband::fork(child_tid, child_pid, parent_tid, parent_pid, cpu);
}

/// `perf_event_exit_event`. Must run BEFORE the task's events are retired, or
/// the record has no ring left to land in. # C: O(events)
pub fn note_exit(tid: u32, pid: u32, parent_tid: u32, parent_pid: u32) {
    let cpu = who().map_or(0, |(_, c)| c);
    sideband::exit(tid, pid, parent_tid, parent_pid, cpu);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `st_dev` splits into the record's two halves the way `MAJOR`/`MINOR` do,
    /// so a consumer matching a record against a `stat(2)` finds the same
    /// device. Checked on the split itself, which is the part that can be
    /// silently wrong.
    #[test]
    fn the_device_number_splits_into_major_and_minor() {
        for (dev, maj, min) in [(0u64, 0u32, 0u32), (0x0803, 8, 3), (0xfe01, 254, 1)] {
            assert_eq!((dev >> 8) as u32, maj, "dev {dev:#x}");
            assert_eq!((dev & 0xff) as u32, min, "dev {dev:#x}");
        }
    }

    #[test]
    fn only_an_executable_mapping_is_a_code_mapping() {
        assert_eq!(PROT_EXEC, 4, "PROT_EXEC");
        assert!(5 & PROT_EXEC != 0, "PROT_READ|PROT_EXEC is code");
        assert!(3 & PROT_EXEC == 0, "PROT_READ|PROT_WRITE is data");
    }

    /// The loader's `VmaProt` reaches the record as the `PROT_*` bits a
    /// consumer reads. A text segment must come out executable, or its record
    /// is routed to `attr.mmap_data` events and `perf report` never sees the
    /// mapping it needs to resolve a sampled IP in the binary.
    #[test]
    fn a_load_segments_prot_reaches_the_record_as_prot_bits() {
        use vmm::VmaProt;
        assert_eq!(prot_bits(VmaProt::READ | VmaProt::EXEC), PROT_READ | PROT_EXEC);
        assert_eq!(prot_bits(VmaProt::READ | VmaProt::WRITE), PROT_READ | PROT_WRITE);
        assert_eq!(prot_bits(VmaProt::READ), PROT_READ);
        assert_eq!(prot_bits(VmaProt::empty()), 0);
        // The bit that decides code-vs-data routing.
        assert!(prot_bits(VmaProt::READ | VmaProt::EXEC) & PROT_EXEC != 0,
                "a text segment is a code mapping");
        assert!(prot_bits(VmaProt::READ | VmaProt::WRITE) & PROT_EXEC == 0,
                "a data segment is not");
    }
}
