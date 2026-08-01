// What the builder is told about the dying process.
//
// Everything the image needs arrives here already snapshotted: register blocks
// as bytes, one descriptor per dumped mapping, the auxiliary vector as bytes,
// and a reader the builder pulls mapping contents through. The builder never
// reaches into a live task, so every layout decision it makes is reachable from
// a hosted test.

use super::layout::CoreArch;

/// Mapping is readable; sets `PF_R` on its program header.
pub const SEG_READ:  u32 = 1 << 0;
/// Mapping is writable; sets `PF_W`.
pub const SEG_WRITE: u32 = 1 << 1;
/// Mapping is executable; sets `PF_X`.
pub const SEG_EXEC:  u32 = 1 << 2;

/// Source of a dumped mapping's contents.
///
/// A hole — a page the reader cannot produce — is written as zeroes rather than
/// shortening the segment, so every program header's `p_filesz` stays honest.
pub trait CoreMem {
    /// Bytes of `buf` filled from `va` onward; a short count leaves a hole.
    fn read(&mut self, va: u64, buf: &mut [u8]) -> usize;
}

impl<F: FnMut(u64, &mut [u8]) -> usize> CoreMem for F {
    fn read(&mut self, va: u64, buf: &mut [u8]) -> usize { self(va, buf) }
}

/// A `timeval` as `elf_prstatus` carries it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CoreTimeval { pub sec: i64, pub usec: i64 }

/// The four CPU-time fields `elf_prstatus` carries.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct CoreTimes {
    pub utime: CoreTimeval,
    pub stime: CoreTimeval,
    pub cutime: CoreTimeval,
    pub cstime: CoreTimeval,
}

/// Numeric `pr_state`, which `pr_sname` and `pr_zomb` are derived from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoreState { Running, Sleeping, DiskSleep, Stopped, Zombie, Paging }

impl CoreState {
    /// Index `pr_state` stores and `pr_sname` looks up.
    /// # C: O(1)
    pub const fn index(self) -> u8 {
        match self {
            CoreState::Running   => 0,
            CoreState::Sleeping  => 1,
            CoreState::DiskSleep => 2,
            CoreState::Stopped   => 3,
            CoreState::Zombie    => 4,
            CoreState::Paging    => 5,
        }
    }
}

/// The file a mapping was faulted from, as `NT_FILE` names it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreSegFile<'a> {
    /// Path a debugger reopens to recover the mapping's unwritten pages.
    pub path: &'a [u8],
    /// Mapping's starting offset into that file, in pages.
    pub pgoff_pages: u64,
}

/// One mapping of the dying process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreSegment<'a> {
    pub start: u64,
    pub end: u64,
    /// `SEG_READ` / `SEG_WRITE` / `SEG_EXEC`.
    pub prot: u32,
    /// Bytes of the mapping whose contents reach the file. Zero elides the
    /// contents while keeping the mapping's address range described.
    pub dump_size: u64,
    pub file: Option<CoreSegFile<'a>>,
}

impl<'a> CoreSegment<'a> {
    /// Bytes the mapping spans in memory.
    /// # C: O(1)
    pub const fn memsz(&self) -> u64 { self.end - self.start }
}

/// One thread's register state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreThread<'a> {
    /// Thread id `pr_pid` carries; the dumping thread's own id for the first.
    pub tid: i32,
    /// Serialised register block, `CoreArch::gregset_bytes()` long.
    pub regs: &'a [u8],
    /// Serialised floating-point block; its presence sets `pr_fpvalid`.
    pub fpregs: Option<&'a [u8]>,
    /// Extended state, emitted as `NT_X86_XSTATE`. Meaningful on x86-64 only.
    pub xstate: Option<&'a [u8]>,
}

/// Who the dying process was.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoreIdentity<'a> {
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub sid: i32,
    pub uid: u32,
    pub gid: u32,
    /// Killing signal, which both `pr_info.si_signo` and `pr_cursig` carry.
    pub signo: i32,
    /// First word of the pending-signal mask.
    pub sigpend: u64,
    /// First word of the blocked-signal mask.
    pub sighold: u64,
    pub state: CoreState,
    pub nice: i8,
    /// Task flags `pr_flag` carries.
    pub flag: u64,
    /// Command name; truncated to fit `pr_fname` with its terminator.
    pub comm: &'a [u8],
    /// Raw argument block; NULs become spaces, truncated to fit `pr_psargs`.
    pub psargs: &'a [u8],
    pub times: CoreTimes,
}

/// Everything the image is built from.
pub struct CoreImageInput<'a> {
    pub arch: CoreArch,
    pub identity: CoreIdentity<'a>,
    /// Dumping thread first; a debugger reads its registers as the crash site.
    pub threads: &'a [CoreThread<'a>],
    /// Mappings, in ascending address order.
    pub segments: &'a [CoreSegment<'a>],
    /// Auxiliary vector as the loader left it, key/value pairs through `AT_NULL`.
    pub auxv: &'a [u8],
    /// Signal descriptor, emitted as `NT_SIGINFO`.
    pub siginfo: Option<&'a [u8]>,
}

/// Why an image could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoreImageError {
    /// No thread to attribute the crash to; a core file without `NT_PRSTATUS`
    /// tells a debugger nothing.
    NoThreads,
    /// Register block does not match the arch's register file.
    RegsLen,
    /// Floating-point block does not match the arch's.
    FpregsLen,
    /// Signal descriptor is not the size the note fixes.
    SiginfoLen,
    /// Mapping ends before it starts.
    SegmentRange,
    /// Mapping is not page-aligned, so its program header could not be aligned.
    SegmentAlign,
    /// More contents requested than the mapping spans.
    SegmentDumpSize,
}
