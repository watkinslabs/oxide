// x86_64 TSS I/O permission bitmap — the hardware half of `ioperm(2)` /
// `iopl(2)`.
//
// Intel SDM Vol. 1 §19.5.2: when CPL > IOPL, an `in`/`out`/`ins`/`outs` to
// port P consults the bit at `TSS_base + io_bitmap_base + P/8`, bit `P%8`.
// A CLEAR bit permits the access; a SET bit raises #GP. The CPU reads one
// byte PAST the last addressed byte when the access straddles a byte
// boundary, so the map is one `u64` longer than 65536 bits and that trailing
// word must be all-ones and inside the descriptor limit.
//
// Two windows live in the TSS, exactly as the reference lays them out:
//
// | window | offset | contents | selected when |
// |---|---|---|---|
// | `bitmap` | `IO_BITMAP_OFFSET_VALID_MAP` | the running task's map | task has an `ioperm` map |
// | `mapall` | `IO_BITMAP_OFFSET_VALID_ALL` | all zero (permit all) + `!0` tail | task called `iopl(3)` |
// | none | `IO_BITMAP_OFFSET_INVALID` | past the descriptor limit | every other task |
//
// `iopl(3)` is emulated through `mapall` rather than by raising the EFLAGS
// IOPL field, because a real IOPL=3 would also hand user mode `cli`/`sti`.
// The observable grant (all 65536 ports) is identical; the interrupt-flag
// privilege is not granted. This mirrors the reference.
//
// The per-CPU TSS statics live in `super` (`tss.rs`) and are ZERO-initialised
// so the 64 × 16 KiB of bitmap lands in `.bss` rather than the kernel image.
// `init_for_cpu` establishes the real contents (deny-all map, `mapall` tail,
// invalid base) and MUST run before that CPU's `ltr` — a zero `iomap_base`
// would point the window at the TSS header itself, whose bytes are mostly
// zero, i.e. permit ports from ring 3.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{TssFull, NR_TSS};

/// Ports covered by an x86 I/O permission bitmap: the whole 16-bit port space.
pub const IO_BITMAP_BITS: usize = 65536;
/// Bytes needed for `IO_BITMAP_BITS` permission bits.
pub const IO_BITMAP_BYTES: usize = IO_BITMAP_BITS / 8;
/// `u64` words needed for `IO_BITMAP_BYTES`.
pub const IO_BITMAP_LONGS: usize = IO_BITMAP_BYTES / core::mem::size_of::<u64>();

/// Both TSS-resident I/O windows. `bitmap` carries the running task's
/// permissions; `mapall` is the constant permit-everything map used for
/// `iopl(3)`. Each carries one extra `u64` because the CPU may read a byte
/// past the last addressed one.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TssIoBitmap {
    pub bitmap: [u64; IO_BITMAP_LONGS + 1],
    pub mapall: [u64; IO_BITMAP_LONGS + 1],
}

impl TssIoBitmap {
    /// All-zero image, matching the `.bss` state of the TSS statics.
    /// `init_for_cpu` turns it into the real deny-all layout.
    /// # C: O(1)
    pub const fn zeroed() -> Self {
        Self { bitmap: [0; IO_BITMAP_LONGS + 1], mapall: [0; IO_BITMAP_LONGS + 1] }
    }
}

/// `io_bitmap_base` value selecting the per-task map.
pub const IO_BITMAP_OFFSET_VALID_MAP: u16 = core::mem::offset_of!(TssFull, io.bitmap) as u16;
/// `io_bitmap_base` value selecting the permit-everything map (`iopl(3)`).
pub const IO_BITMAP_OFFSET_VALID_ALL: u16 = core::mem::offset_of!(TssFull, io.mapall) as u16;

/// TSS descriptor limit (inclusive last valid byte). Covers through the end
/// of `mapall` including its trailing all-ones word, so both windows are
/// addressable; `gdt::install_kernel_gdt` stamps this into every per-CPU TSS
/// descriptor.
pub const KERNEL_TSS_LIMIT: u32 =
    IO_BITMAP_OFFSET_VALID_ALL as u32 + IO_BITMAP_BYTES as u32 + core::mem::size_of::<u64>() as u32 - 1;

/// `io_bitmap_base` value that disables port access entirely: one past the
/// descriptor limit, so any bitmap consult by the CPU raises #GP.
pub const IO_BITMAP_OFFSET_INVALID: u16 = (KERNEL_TSS_LIMIT + 1) as u16;

/// Per-CPU record of the sequence number of the map last copied into that
/// CPU's TSS. A switch back to the same task with an unchanged map skips the
/// copy entirely, which is what keeps `ioperm` users off a per-switch memcpy.
/// Zero is the never-copied sentinel; live sequences start at 1.
static PREV_SEQUENCE: [AtomicU64; NR_TSS] = [const { AtomicU64::new(0) }; NR_TSS];

/// Per-CPU record of how many bytes of that CPU's TSS `bitmap` window the
/// last copy dirtied. The next copy must cover at least that much or stale
/// permit bits from the previous task would survive under the new one.
static PREV_MAX: [AtomicU32; NR_TSS] = [const { AtomicU32::new(0) }; NR_TSS];

/// Establish CPU `cpu`'s I/O windows: deny every port, publish the
/// permit-everything map's mandatory trailing all-ones word, and park
/// `io_bitmap_base` outside the descriptor limit.
///
/// # SAFETY: caller owns CPU `cpu`'s bring-up and is its sole writer; must
/// run BEFORE that CPU's `ltr`, since a zeroed `iomap_base` would aim the
/// hardware's port check at the TSS header.
/// # C: O(IO_BITMAP_LONGS)
/// # Ctx: pre-init | AP bring-up, IRQ-off
pub unsafe fn init_for_cpu(cpu: usize) {
    // SAFETY: bring-up owner is the sole writer of its own TSS slot per this fn's contract.
    let t = unsafe { super::tss_mut(cpu) };
    t.hw.iomap_base = IO_BITMAP_OFFSET_INVALID;
    t.io.bitmap.fill(u64::MAX);
    t.io.mapall.fill(0);
    t.io.mapall[IO_BITMAP_LONGS] = u64::MAX;
    PREV_SEQUENCE[cpu.min(NR_TSS - 1)].store(0, Ordering::Relaxed);
    PREV_MAX[cpu.min(NR_TSS - 1)].store(0, Ordering::Relaxed);
}

/// Park this CPU's `io_bitmap_base` outside the descriptor limit, so any
/// ring-3 port access raises #GP.
///
/// The window is moved rather than the map cleared: the reference does the
/// same, and it is what makes the common switch (task with no port access)
/// a single 2-byte store instead of an 8 KiB memset.
///
/// # SAFETY: caller runs on the CPU whose TSS is rewritten, preempt-off, at
/// CPL 0; the store is a single aligned 2-byte write the CPU re-reads only on
/// its own ring-3 port access.
/// # C: O(1)
/// # Ctx: process|context-switch path, preempt-off
pub unsafe fn invalidate(cpu: usize) {
    // SAFETY: this CPU is the sole writer of its own TSS slot; single 2-byte store.
    let t = unsafe { super::tss_mut(cpu) };
    t.hw.iomap_base = IO_BITMAP_OFFSET_INVALID;
}

/// Point this CPU's window at the permit-everything map — the `iopl(3)` grant.
///
/// # SAFETY: same contract as `invalidate`: owning CPU, preempt-off, CPL 0.
/// # C: O(1)
/// # Ctx: process|context-switch path, preempt-off
pub unsafe fn set_all(cpu: usize) {
    // SAFETY: this CPU is the sole writer of its own TSS slot; single 2-byte store.
    let t = unsafe { super::tss_mut(cpu) };
    t.hw.iomap_base = IO_BITMAP_OFFSET_VALID_ALL;
}

/// Copy `bytes` (a task's permission map, set bit = denied) into this CPU's
/// TSS window and select it. `max` is the number of leading bytes that carry
/// any permitted bit; `sequence` identifies the map revision.
///
/// The copy covers `max(prev_max, max)` bytes so a shorter incoming map still
/// overwrites the trailing permits the previous map left behind, and is
/// skipped entirely when `sequence` matches what this CPU already holds.
///
/// # SAFETY: caller runs on the CPU whose TSS is rewritten, preempt-off, at
/// CPL 0, and `bytes` is a live `IO_BITMAP_BYTES`-long image for the duration.
/// # C: O(max(prev_max, max))
/// # Ctx: process|context-switch path, preempt-off
pub unsafe fn set_map(cpu: usize, bytes: &[u8], max: u32, sequence: u64) {
    let c = cpu.min(NR_TSS - 1);
    // SAFETY: this CPU is the sole writer of its own TSS slot per this fn's contract.
    let t = unsafe { super::tss_mut(c) };
    if PREV_SEQUENCE[c].load(Ordering::Relaxed) != sequence {
        let prev = PREV_MAX[c].load(Ordering::Relaxed);
        let n = (prev.max(max) as usize).min(bytes.len()).min(IO_BITMAP_BYTES);
        // SAFETY: `t.io.bitmap` is IO_BITMAP_BYTES + 8 bytes long and `n` is
        // clamped to IO_BITMAP_BYTES and to the source length, so both ranges
        // are in bounds and cannot overlap (distinct allocations).
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), t.io.bitmap.as_mut_ptr() as *mut u8, n); }
        PREV_MAX[c].store(max, Ordering::Relaxed);
        PREV_SEQUENCE[c].store(sequence, Ordering::Relaxed);
    }
    t.hw.iomap_base = IO_BITMAP_OFFSET_VALID_MAP;
}

/// Program THIS CPU's I/O window for the task that is about to run in user
/// mode. `iopl_level` is the task's emulated IOPL (3 permits every port);
/// `map` is its `ioperm` image as `(bytes, max, sequence)`.
///
/// One entry point rather than three so the window can never be left
/// half-programmed: every path through it ends with `iomap_base` describing
/// exactly the grant the task holds, and a task with neither grant lands on
/// `IO_BITMAP_OFFSET_INVALID`.
///
/// # SAFETY: caller runs on the CPU being programmed with preemption
/// disabled at CPL 0, and `map`'s slice stays live for the call.
/// # C: O(bitmap bytes copied), zero when the sequence is unchanged
/// # Ctx: process|context-switch path, preempt-off
pub unsafe fn tss_update_io_bitmap(iopl_level: u8, map: Option<(&[u8], u32, u64)>) {
    use hal::CpuOps;
    let cpu = crate::X86CpuOps::current_cpu() as usize;
    match (iopl_level, map) {
        // `iopl(3)`: every port, via the constant permit-all window.
        (3, _) => {
            // SAFETY: owning CPU, preempt-off at CPL 0 per this fn's contract; single 2-byte store.
            unsafe { set_all(cpu) }
        }
        (_, Some((bytes, max, seq))) => {
            // SAFETY: owning CPU, preempt-off, and `bytes` outlives the call per this fn's contract.
            unsafe { set_map(cpu, bytes, max, seq) }
        }
        // SAFETY: owning CPU, preempt-off per this fn's contract.
        _ => unsafe { invalidate(cpu) },
    }
}

/// Read CPU `cpu`'s live `io_bitmap_base`. Test-only: the kernel never needs
/// the value back, the CPU consults it directly.
/// # C: O(1)
#[cfg(test)]
pub fn iomap_base(cpu: usize) -> u16 {
    // SAFETY: hosted single-threaded test read of a u16 field.
    unsafe { super::tss_mut(cpu.min(NR_TSS - 1)) }.hw.iomap_base
}

/// Read one byte of CPU `cpu`'s live TSS permission window. Test-only.
/// # C: O(1)
#[cfg(test)]
pub fn map_byte(cpu: usize, i: usize) -> u8 {
    // SAFETY: hosted single-threaded test read; `i` bounded by the caller below.
    let t = unsafe { super::tss_mut(cpu.min(NR_TSS - 1)) };
    // SAFETY: `i` is clamped into the IO_BITMAP_BYTES + 8 byte window.
    unsafe { *(t.io.bitmap.as_ptr() as *const u8).add(i.min(IO_BITMAP_BYTES + 7)) }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use super::super::Tss64;

    /// Offsets and the limit are hardware contracts: the CPU indexes the
    /// window by `io_bitmap_base` and refuses anything past the descriptor
    /// limit. An `INVALID` base that landed INSIDE the limit would silently
    /// permit ports; a limit that stopped short of `mapall`'s tail would #GP
    /// on a legitimate `iopl(3)` access to the top of the port space.
    #[test]
    fn window_offsets_and_limit_are_the_hardware_layout() {
        assert_eq!(IO_BITMAP_BITS, 65536);
        assert_eq!(IO_BITMAP_BYTES, 8192);
        assert_eq!(IO_BITMAP_LONGS, 1024);
        assert_eq!(IO_BITMAP_OFFSET_VALID_MAP as usize, core::mem::size_of::<Tss64>());
        assert_eq!(IO_BITMAP_OFFSET_VALID_ALL as usize,
                   core::mem::size_of::<Tss64>() + (IO_BITMAP_LONGS + 1) * 8);
        // Limit is inclusive, so it is exactly one below the struct size.
        assert_eq!(KERNEL_TSS_LIMIT as usize, core::mem::size_of::<TssFull>() - 1);
        assert_eq!(IO_BITMAP_OFFSET_INVALID as usize, core::mem::size_of::<TssFull>());
        assert!(IO_BITMAP_OFFSET_INVALID as u32 > KERNEL_TSS_LIMIT,
                "the invalid base must sit OUTSIDE the descriptor limit or ports stay open");
    }

    #[test]
    fn init_denies_every_port_and_parks_the_window() {
        let cpu = 7usize;
        // SAFETY: hosted single-threaded test; sole writer of TSS[7].
        unsafe { init_for_cpu(cpu); }
        assert_eq!(iomap_base(cpu), IO_BITMAP_OFFSET_INVALID);
        for i in [0usize, 1, 4095, IO_BITMAP_BYTES - 1] {
            assert_eq!(map_byte(cpu, i), 0xff, "byte {i} must deny after init");
        }
        // The trailing word the CPU may read past the end must be all ones.
        for i in IO_BITMAP_BYTES..IO_BITMAP_BYTES + 8 {
            assert_eq!(map_byte(cpu, i), 0xff, "trailing guard byte {i}");
        }
    }

    #[test]
    fn set_map_copies_once_per_sequence_and_covers_the_previous_max() {
        let cpu = 8usize;
        // SAFETY: hosted single-threaded test; sole writer of TSS[8].
        unsafe { init_for_cpu(cpu); }
        // A map permitting ports 0..8 (byte 0 = 0), everything else denied.
        let mut a = alloc::vec![0xffu8; IO_BITMAP_BYTES];
        a[0] = 0x00;
        // SAFETY: hosted test; `a` outlives the call and the CPU is ours.
        unsafe { set_map(cpu, &a, 8, 1); }
        assert_eq!(iomap_base(cpu), IO_BITMAP_OFFSET_VALID_MAP);
        assert_eq!(map_byte(cpu, 0), 0x00);

        // Same sequence, different content: the copy must be SKIPPED. This is
        // the optimisation the reference relies on, so it must be observable.
        let b = alloc::vec![0x00u8; IO_BITMAP_BYTES];
        // SAFETY: hosted test; same contract as above.
        unsafe { set_map(cpu, &b, 8, 1); }
        assert_eq!(map_byte(cpu, 7), 0xff, "unchanged sequence must not re-copy");

        // A NEW sequence with a SMALLER max must still scrub the bytes the
        // previous map dirtied — otherwise a task that permitted port 0 leaves
        // it permitted for the next task, which is the whole security hole.
        let deny = alloc::vec![0xffu8; IO_BITMAP_BYTES];
        // SAFETY: hosted test; same contract as above.
        unsafe { set_map(cpu, &deny, 0, 2); }
        assert_eq!(map_byte(cpu, 0), 0xff, "prev_max coverage must scrub stale permits");
    }

    #[test]
    fn invalidate_and_set_all_only_move_the_window() {
        let cpu = 9usize;
        // SAFETY: hosted single-threaded test; sole writer of TSS[9].
        unsafe { init_for_cpu(cpu); }
        // SAFETY: hosted test; owning "CPU" is this thread.
        unsafe { set_all(cpu); }
        assert_eq!(iomap_base(cpu), IO_BITMAP_OFFSET_VALID_ALL);
        // SAFETY: hosted test; owning "CPU" is this thread.
        unsafe { invalidate(cpu); }
        assert_eq!(iomap_base(cpu), IO_BITMAP_OFFSET_INVALID);
    }
}
