//! Per-process window-procedure handle table.
//!
//! A window procedure the client hands the kernel is answered with an opaque
//! handle the client stores wherever a `WNDPROC`/`DLGPROC` slot lives, and
//! handed back the real procedure when the client asks. The handle encoding is
//! `0xffff` in the high half-word and the table index in the low one, so a
//! plain function pointer can never be mistaken for a handle.
//!
//! Two return shapes carry the contract and are easy to get backwards:
//! allocation answers the *input procedure unchanged* when it cannot allocate,
//! and the dialog query answers its *input unchanged* when the input is not a
//! handle. Answering zero in either case turns a live procedure into NULL,
//! which is a dialog with dead controls.
use alloc::vec::Vec;
use super::WindowManager;

/// Widest table the low half-word index admits before a handle names a
/// 16-bit procedure instead.
pub const MAX_WINPROCS: usize = 4096;
/// Slots the builtin class procedures reserve, one per `NTUSER_WNDPROC_*`
/// role, published before any client procedure can allocate.
pub const NB_BUILTIN_PROCS: usize = 17;
/// The answer a handle outside the table's range carries: a 16-bit procedure
/// the caller thunks itself rather than a procedure address.
pub const WINPROC_PROC16: u64 = 1;
const HANDLE_TAG: u64 = 0xffff_0000;
const INDEX_MASK: u64 = 0xffff;

/// The handle naming one table index. # C: O(1)
pub const fn make_winproc(index: usize) -> u64 { HANDLE_TAG | (index as u64 & INDEX_MASK) }

/// What one caller-supplied word names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WinProcSlot {
    /// Not a handle this table issued: a procedure address, or a stale one.
    NotAHandle,
    /// A handle whose index lies past the table: a 16-bit procedure.
    Proc16,
    /// A live table entry.
    Index(usize),
}

/// One table entry: the ANSI and Unicode procedures registered for it. Zero
/// means the entry carries no procedure of that flavour.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct Entry { ansi: u64, unicode: u64 }

/// The process's table. Entries are never freed: a process registers few
/// distinct procedures however many windows it creates, so reuse by procedure
/// keeps the table small without per-window accounting.
#[derive(Debug)]
pub struct WinProcs { entries: Vec<Entry> }

impl Default for WinProcs { fn default() -> Self { Self::new() } }

impl WinProcs {
    /// The builtin slots exist from the start, so the first client allocation
    /// cannot take one and a builtin handle is answerable before the client
    /// has published anything. # C: O(NB_BUILTIN_PROCS)
    pub fn new() -> Self { Self { entries: alloc::vec![Entry::default(); NB_BUILTIN_PROCS] } }

    /// Install the builtin class procedures the client published. Slots past
    /// the shorter of the two arrays keep whatever they already carry.
    /// # C: O(NB_BUILTIN_PROCS)
    pub fn publish_builtins(&mut self, ansi: &[u64], unicode: &[u64]) {
        for index in 0..NB_BUILTIN_PROCS {
            self.entries[index] = Entry { ansi: ansi.get(index).copied().unwrap_or(0), unicode: unicode.get(index).copied().unwrap_or(0) };
        }
    }

    /// How many slots are live. # C: O(1)
    pub fn used(&self) -> usize { self.entries.len() }

    /// What one caller word names. A word that is not exactly the handle for
    /// its own low half-word is a procedure address, not a handle.
    /// # C: O(1)
    pub fn slot(&self, handle: u64) -> WinProcSlot {
        let index = (handle & INDEX_MASK) as usize;
        if handle != make_winproc(index) { return WinProcSlot::NotAHandle; }
        if index >= MAX_WINPROCS { return WinProcSlot::Proc16; }
        if index >= self.used() { return WinProcSlot::NotAHandle; }
        WinProcSlot::Index(index)
    }

    /// The entry already registered for one procedure. A builtin slot matches
    /// either flavour because callers confuse the two; a client slot matches
    /// only the flavour asked for. # C: O(N_entries)
    fn find(&self, func: u64, ansi: bool) -> Option<usize> {
        for (index, entry) in self.entries.iter().enumerate().take(NB_BUILTIN_PROCS) {
            if entry.ansi == func || entry.unicode == func { return Some(index); }
        }
        self.entries.iter().enumerate().skip(NB_BUILTIN_PROCS)
            .find(|(_, entry)| if ansi { entry.ansi == func } else { entry.unicode == func })
            .map(|(index, _)| index)
    }

    /// Answer the handle for one procedure, allocating a slot if it has none.
    ///
    /// The input is answered unchanged in every case that allocates nothing:
    /// a null procedure, a word that is already a handle, a 16-bit handle, and
    /// a full table. Zero is never invented.
    /// # C: O(N_entries)
    pub fn alloc(&mut self, func: u64, ansi: bool) -> u64 {
        if func == 0 { return func; }
        match self.slot(func) {
            WinProcSlot::Index(index) => return make_winproc(index),
            WinProcSlot::Proc16 => return func,
            WinProcSlot::NotAHandle => {}
        }
        if let Some(index) = self.find(func, ansi) { return make_winproc(index); }
        if self.entries.len() >= MAX_WINPROCS { return func; }
        let index = self.entries.len();
        self.entries.push(if ansi { Entry { ansi: func, unicode: 0 } } else { Entry { ansi: 0, unicode: func } });
        make_winproc(index)
    }

    /// The dialog procedure one word names. A word that is not a handle is its
    /// own answer; a 16-bit handle answers the thunk placeholder; a live entry
    /// answers the asked-for flavour, which may legitimately be absent.
    /// # C: O(1)
    pub fn dialog_proc(&self, proc: u64, ansi: bool) -> u64 {
        match self.slot(proc) {
            WinProcSlot::NotAHandle => proc,
            WinProcSlot::Proc16 => WINPROC_PROC16,
            WinProcSlot::Index(index) => if ansi { self.entries[index].ansi } else { self.entries[index].unicode },
        }
    }
}

impl WindowManager {
    /// # C: O(NB_BUILTIN_PROCS)
    pub fn publish_builtin_winprocs(&mut self, ansi: &[u64], unicode: &[u64]) { self.winprocs.publish_builtins(ansi, unicode); }
    /// # C: O(N_entries)
    pub fn alloc_winproc(&mut self, func: u64, ansi: bool) -> u64 { self.winprocs.alloc(func, ansi) }
    /// # C: O(1)
    pub fn dialog_proc(&self, proc: u64, ansi: bool) -> u64 { self.winprocs.dialog_proc(proc, ansi) }
}

#[cfg(test)]
#[path = "tests/winproc.rs"]
mod tests;
