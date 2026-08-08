// Directory-iteration shapes for [`super::FileOps::iterate_dir`]: the emitter
// callback, the per-call context that tracks the cursor and the fill result,
// and the hole/data selector for `seek_hole_data`. Split out of the parent so
// the vtable file stays a trait declaration.

extern crate alloc;

use crate::types::FileType;

/// `SEEK_HOLE`/`SEEK_DATA` selector for [`super::FileOps::seek_hole_data`] (Linux
/// `lseek(2)` whence `4`/`3`). `Data` finds the next byte ≥ `offset` that is
/// part of a data extent; `Hole` finds the next hole (or the implicit hole at
/// EOF). # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HoleOrData {
    /// `SEEK_DATA` — next data byte at/after `offset`.
    Data,
    /// `SEEK_HOLE` — next hole at/after `offset`.
    Hole,
}

/// `filldir`-style sink (Linux `struct dir_context.actor` / `filldir_t`): the
/// callback `getdents` installs to pack one directory entry into the user
/// buffer. `emit` returns `false` when the buffer cannot hold the entry — the
/// driving `iterate` then stops. # C: backend-dependent
pub trait DirEmit {
    /// Pack one entry `(name, ino, d_type)` whose resume cookie is `next_pos`.
    /// Return `false` (buffer full) to stop the walk. # C: O(reclen)
    fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool;

    /// Same, on the raw `DT_*` channel Linux's `filldir` actually carries, so a
    /// backend that genuinely cannot type an entry can say `DT_UNKNOWN` instead
    /// of being forced to invent an inode type. The default forwards to
    /// [`Self::emit`] (lossy for `DT_UNKNOWN`); the getdents packer overrides it
    /// and writes the byte through untouched. # C: O(reclen)
    fn emit_dt(&mut self, name: &str, ino: u64, d_type: crate::dirent::DType, next_pos: u64) -> bool {
        self.emit(name, ino, d_type.to_file_type_lossy(), next_pos)
    }

    /// Receive VFS-owned readdir progress for an armed diagnostic operation.
    /// Default keeps backends and normal actors independent of diagnostics. # C: O(1)
    #[cfg(feature = "debug-getdents")]
    fn debug_getdents_progress(&mut self, _backend: DirDebugBackend, _block: u32,
                                _entries: u64, _pos: u64) {}
}

/// Backend identity carried by the VFS readdir diagnostic callback. # C: O(1)
#[cfg(feature = "debug-getdents")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DirDebugBackend { Unknown, Ext4 }

#[cfg(feature = "debug-getdents")]
impl DirDebugBackend {
    /// Stable diagnostic label; no filesystem string registry exists. # C: O(1)
    pub const fn label(self) -> &'static [u8] {
        match self { Self::Unknown => b"unknown", Self::Ext4 => b"ext4" }
    }
}

/// `struct dir_context`: the readdir cursor +
/// actor threaded through [`super::FileOps::iterate`]. `pos` is the resume cookie the
/// backend reads to know where to start and that [`Self::emit`] advances as
/// each entry is accepted; `actor` is the buffer-packing sink. # C: O(1)
pub struct DirContext<'a> {
    /// `ctx->pos` — current readdir cursor / resume cookie. The backend reads it
    /// to skip already-emitted entries; `emit` advances it. # C: O(1)
    pub pos: u64,
    actor: &'a mut dyn DirEmit,
    #[cfg(feature = "debug-getdents")]
    debug_backend: DirDebugBackend,
    #[cfg(feature = "debug-getdents")]
    debug_block: u32,
    #[cfg(feature = "debug-getdents")]
    debug_emitted: u64,
}

#[cfg(feature = "debug-getdents-detail")]
pub(crate) const DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL: u64 = 256;
#[cfg(feature = "debug-getdents")]
const DEBUG_GETDENTS_UNKNOWN_BACKEND: DirDebugBackend = DirDebugBackend::Unknown;
#[cfg(feature = "debug-getdents")]
const DEBUG_GETDENTS_NO_BLOCK: u32 = u32::MAX;

#[cfg(feature = "debug-getdents-detail")]
pub(crate) const fn debug_getdents_progress_due(emitted: u64) -> bool {
    emitted != 0 && emitted % DEBUG_GETDENTS_PROGRESS_ENTRY_INTERVAL == 0
}

impl<'a> DirContext<'a> {
    /// Build a context resuming at cookie `pos`, packing through `actor`. # C: O(1)
    pub fn new(pos: u64, actor: &'a mut dyn DirEmit) -> Self {
        Self {
            pos, actor,
            #[cfg(feature = "debug-getdents")]
            debug_backend: DEBUG_GETDENTS_UNKNOWN_BACKEND,
            #[cfg(feature = "debug-getdents")]
            debug_block: DEBUG_GETDENTS_NO_BLOCK,
            #[cfg(feature = "debug-getdents")]
            debug_emitted: 0,
        }
    }

    /// Record the backend-owned iteration location for the VFS progress trace.
    /// No output occurs here; `emit` owns the bounded trace cadence. # C: O(1)
    #[cfg(feature = "debug-getdents")]
    pub fn debug_set_backend_block(&mut self, backend: DirDebugBackend, block: u32) {
        self.debug_backend = backend;
        self.debug_block = block;
        self.actor.debug_getdents_progress(backend, block, self.debug_emitted, self.pos);
    }

    /// `dir_emit` — offer one entry to the actor. On accept (`true`), advance
    /// `pos` to `next_pos` (the resume cookie just past this entry) so a stop on
    /// the FOLLOWING entry leaves `pos` at the correct resume point. On reject
    /// (`false`, buffer full) leave `pos` unchanged and return `false` so the
    /// backend stops. # C: O(reclen)
    pub fn emit(&mut self, name: &str, ino: u64, d_type: FileType, next_pos: u64) -> bool {
        self.emit_dt(name, ino, crate::dirent::DType::from_file_type(d_type), next_pos)
    }

    /// `dir_emit` on the raw `DT_*` channel — for backends that can report
    /// `DT_UNKNOWN` honestly. Same cursor contract as [`Self::emit`].
    /// # C: O(reclen)
    pub fn emit_dt(&mut self, name: &str, ino: u64, d_type: crate::dirent::DType, next_pos: u64) -> bool {
        if self.actor.emit_dt(name, ino, d_type, next_pos) {
            self.pos = next_pos;
            #[cfg(feature = "debug-getdents")]
            {
                self.debug_emitted += 1;
                self.actor.debug_getdents_progress(self.debug_backend, self.debug_block,
                                                   self.debug_emitted, self.pos);
                #[cfg(feature = "debug-getdents-detail")]
                if debug_getdents_progress_due(self.debug_emitted) {
                    klog::write_raw(b"[GETDENTS-PROGRESS] backend=");
                    klog::write_raw(self.debug_backend.label());
                    klog::write_raw(b" block=");
                    if self.debug_block == DEBUG_GETDENTS_NO_BLOCK { klog::write_raw(b"none"); }
                    else { klog::write_dec_u64(self.debug_block as u64); }
                    klog::write_raw(b" entries=");
                    klog::write_dec_u64(self.debug_emitted);
                    klog::write_raw(b" fpos=");
                    klog::write_dec_u64(self.pos);
                    klog::write_raw(b"\n");
                }
            }
            true
        } else { false }
    }
}
