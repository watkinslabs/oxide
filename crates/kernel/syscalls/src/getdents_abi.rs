// `getdents(2)`/`getdents64(2)` record ABI + fill accounting — Linux
// `fs/readdir.c` (`filldir`, `filldir64`, `verify_dirent_name`,
// `SYSCALL_DEFINE3(getdents)`, `SYSCALL_DEFINE3(getdents64)`) and
// `include/linux/dirent.h` (v7.2.0-rc4).
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: slot file
// `217_getdents64.rs` is kernel-only, so the record layout, the reclen
// alignment, the too-small-buffer EINVAL and the "bytes already written win
// over a late error" return rule were all unreachable from `cargo test`. Those
// are exactly the rules a caller iterating by `d_reclen` desynchronises on, so
// they live here and the slot stays a thin shim (docs/53).
//
// Module manifest:
//   this file  — layout, reclen, name verification, record writer, fill
//                accounting, and the syscall return rule.
//   tests/     — hosted unit tests (`getdents_abi/tests.rs`).

use syscall::errno::Errno;

#[cfg(test)]
mod tests;

/// Linux `PATH_MAX` (`include/uapi/linux/limits.h`) — `verify_dirent_name`
/// rejects a name at or above this length as filesystem corruption.
pub const PATH_MAX: usize = 4096;

/// `linux_dirent` (`fs/readdir.c`): `d_ino`@0 (unsigned long), `d_off`@8
/// (unsigned long), `d_reclen`@16 (unsigned short), `d_name`@18. `d_type` has
/// NO field: it is smuggled into the record's LAST byte (`d_reclen - 1`).
pub const DIRENT_NAME_OFF: usize = 18;

/// `linux_dirent64` (`include/linux/dirent.h`): `d_ino`@0 (u64), `d_off`@8
/// (s64), `d_reclen`@16 (unsigned short), `d_type`@18 (unsigned char),
/// `d_name`@19.
pub const DIRENT64_NAME_OFF: usize = 19;

/// `d_type` field offset inside a `linux_dirent64` record.
pub const DIRENT64_TYPE_OFF: usize = 18;

/// Record alignment: Linux rounds both layouts up with `ALIGN(.., sizeof(long))`
/// (`filldir`) / `ALIGN(.., sizeof(u64))` (`filldir64`); both are 8 on LP64.
pub const DIRENT_ALIGN: usize = 8;

/// Widest record either layout can produce: the longest name
/// `verify_dirent_name` admits (`PATH_MAX - 1`) plus header, NUL and pad.
pub const MAX_RECLEN: usize = (DIRENT64_NAME_OFF + (PATH_MAX - 1) + 1 + DIRENT_ALIGN - 1)
    & !(DIRENT_ALIGN - 1);

/// Which of the two `getdents` record layouts a call packs. The layouts are
/// NOT interchangeable: `d_type` moves, the name starts one byte earlier in the
/// legacy form, and a caller walking by `d_reclen` desynchronises on the whole
/// buffer if either is wrong.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DirentLayout {
    /// `linux_dirent` — slot 78 `getdents(2)`.
    Legacy,
    /// `linux_dirent64` — slot 217 `getdents64(2)`.
    Modern,
}

impl DirentLayout {
    /// Byte offset of `d_name` within the record. # C: O(1)
    pub const fn name_off(self) -> usize {
        match self { Self::Legacy => DIRENT_NAME_OFF, Self::Modern => DIRENT64_NAME_OFF }
    }

    /// Linux `filldir`: `ALIGN(offsetof(d_name[namlen + 2]), sizeof(long))` —
    /// the `+2` reserves the name's NUL *and* the trailing `d_type` byte.
    /// `filldir64`: `ALIGN(offsetof(d_name[namlen + 1]), sizeof(u64))` — `+1`
    /// for the NUL, `d_type` already having its own header field.
    /// # C: O(1)
    pub const fn reclen(self, name_len: usize) -> usize {
        let raw = match self {
            Self::Legacy => DIRENT_NAME_OFF + name_len + 2,
            Self::Modern => DIRENT64_NAME_OFF + name_len + 1,
        };
        (raw + DIRENT_ALIGN - 1) & !(DIRENT_ALIGN - 1)
    }

    /// Byte offset of `d_type` inside a record of `reclen` bytes. Legacy puts
    /// it in the last byte; `linux_dirent64` has a real field at 18. # C: O(1)
    pub const fn dtype_off(self, reclen: usize) -> usize {
        match self { Self::Legacy => reclen - 1, Self::Modern => DIRENT64_TYPE_OFF }
    }
}

/// Linux `verify_dirent_name` (`fs/readdir.c`): a directory entry whose name is
/// empty, at least `PATH_MAX` long, or contains `/` is filesystem corruption
/// that would confuse every caller of `readdir(3)`; the walk stops with EIO
/// rather than handing the name out. # C: O(name.len())
pub fn verify_dirent_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() || name.len() >= PATH_MAX { return Err(Errno::Eio); }
    if name.contains(&b'/') { return Err(Errno::Eio); }
    Ok(())
}

/// Write one record at the front of `buf`, in `layout`'s exact byte order.
/// `off` is the `d_off` resume cookie (Linux writes the *next* entry's position
/// there, so a caller can `lseek` to it and resume immediately after this
/// entry). Returns the record length, or `None` when `buf` cannot hold it.
///
/// Bytes between the name's NUL and the end of the record are zeroed: the
/// buffer handed back to userspace must not leak whatever it held before.
/// # C: O(reclen)
pub fn write_record(buf: &mut [u8], layout: DirentLayout, ino: u64, off: u64,
                    d_type: u8, name: &[u8]) -> Option<usize> {
    let reclen = layout.reclen(name.len());
    if buf.len() < reclen { return None; }
    let rec = &mut buf[..reclen];
    for b in rec.iter_mut() { *b = 0; }
    rec[0..8].copy_from_slice(&ino.to_le_bytes());
    rec[8..16].copy_from_slice(&off.to_le_bytes());
    rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    let name_off = layout.name_off();
    rec[name_off..name_off + name.len()].copy_from_slice(name);
    rec[layout.dtype_off(reclen)] = d_type;
    Some(reclen)
}

/// What the fill callback decided about one offered entry, mirroring
/// `filldir`'s `true`/`false` return plus the `buf->error` it leaves behind.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Fill {
    /// Record written; `usize` bytes consumed. Iteration continues.
    Wrote(usize),
    /// Record refused — buffer full, or the name failed verification.
    /// Iteration stops; [`DirentFill::error`] names why.
    Stop,
}

/// `struct getdents_callback{,64}` — the running fill state. Owns the
/// capacity accounting and the sticky `buf->error`, so the syscall's return
/// value is a pure function of this state plus the iterate result.
#[derive(Debug)]
pub struct DirentFill {
    layout: DirentLayout,
    capacity: usize,
    written: usize,
    /// Byte offset of the last record written, so the syscall tail can rewrite
    /// its `d_off` (Linux `put_user(buf.ctx.pos, &lastdirent->d_off)`).
    last_rec: Option<usize>,
    /// Linux `buf->error`. `filldir` parks `-EINVAL` here before every capacity
    /// test and never clears it on success, so it only ever surfaces when
    /// nothing was written at all.
    error: Option<Errno>,
}

impl DirentFill {
    /// # C: O(1)
    pub fn new(layout: DirentLayout, capacity: usize) -> Self {
        Self { layout, capacity, written: 0, last_rec: None, error: None }
    }

    /// Bytes packed so far — Linux's `count - ctx->count`. # C: O(1)
    pub fn written(&self) -> usize { self.written }

    /// The `count` argument: the exact byte span the caller's buffer spans.
    /// # C: O(1)
    pub fn capacity(&self) -> usize { self.capacity }

    /// Sticky `buf->error`. # C: O(1)
    pub fn error(&self) -> Option<Errno> { self.error }

    /// Record length this entry would occupy. # C: O(1)
    pub fn reclen(&self, name_len: usize) -> usize { self.layout.reclen(name_len) }

    /// Offer one entry, writing it into `out` (the user buffer, already
    /// positioned at its base) at [`Self::written`]. Linux order: verify the
    /// name (EIO), park `-EINVAL`, then test the capacity. # C: O(reclen)
    pub fn offer(&mut self, out: &mut [u8], ino: u64, off: u64, d_type: u8, name: &[u8]) -> Fill {
        if let Err(e) = verify_dirent_name(name) { self.error = Some(e); return Fill::Stop; }
        let reclen = self.layout.reclen(name.len());
        // Linux parks -EINVAL before the capacity test ("only used if we fail")
        // and leaves it there on success — harmless, since a non-zero byte
        // count always wins in `ret`.
        self.error = Some(Errno::Einval);
        if reclen > self.capacity - self.written { return Fill::Stop; }
        match write_record(&mut out[self.written..], self.layout, ino, off, d_type, name) {
            Some(n) => { self.last_rec = Some(self.written); self.written += n; Fill::Wrote(n) }
            None    => { self.error = Some(Errno::Efault); Fill::Stop }
        }
    }

    /// Linux's syscall tail rewrites the LAST record's `d_off` with the final
    /// `ctx->pos`:
    ///
    /// ```text
    /// lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;
    /// put_user(buf.ctx.pos, &lastdirent->d_off);
    /// ```
    ///
    /// so `telldir(3)` after the last entry of a directory yields the
    /// end-of-directory position rather than a cookie just past the last
    /// record. Returns `false` if the write could not happen (EFAULT).
    /// # C: O(1)
    pub fn seal_last_d_off(&self, out: &mut [u8], final_pos: u64) -> bool {
        let Some(at) = self.last_rec else { return true; };
        if at + 16 > out.len() { return false; }
        out[at + 8..at + 16].copy_from_slice(&final_pos.to_le_bytes());
        true
    }

    /// Linux's syscall tail:
    ///
    /// ```text
    /// error = iterate_dir(...);
    /// if (error >= 0) error = buf.error;
    /// if (buf.prev_reclen) error = count - buf.ctx.count;
    /// ```
    ///
    /// So bytes already packed ALWAYS win: an EIO from the backend, or a fault
    /// on the record after them, still returns a short byte count rather than
    /// discarding entries the caller can already use. Only when nothing was
    /// written does an error surface — the iterate error first, then the fill
    /// error (`EINVAL` for "buffer too small for even one entry", which a
    /// caller must not confuse with the `0` that means end-of-directory).
    /// `iter_errno` is the backend's error as a POSITIVE Linux errno.
    /// # C: O(1)
    pub fn ret(&self, iter_errno: Option<i32>) -> i64 {
        if self.written > 0 { return self.written as i64; }
        if let Some(e) = iter_errno { return -(e as i64); }
        if let Some(e) = self.error { return -(e.as_i32() as i64); }
        0
    }
}

/// Linux `filldir`/`filldir64` abandon the walk when a signal is pending and at
/// least one record is already packed (`prev_reclen && signal_pending`), so a
/// huge directory cannot delay signal delivery. The already-packed bytes are
/// returned as a short read — legal for `getdents(2)`, which never promises to
/// drain the directory in one call. Nothing is dropped: `d_off` still resumes
/// at the entry that was not emitted. # C: O(1)
pub fn interrupt_stops_fill(written: usize, signal_pending: bool) -> bool {
    written > 0 && signal_pending
}

/// Linux declares `count` as `unsigned int`, so a 64-bit register argument is
/// truncated before any capacity arithmetic sees it. # C: O(1)
pub fn count_arg(raw: u64) -> usize { raw as u32 as usize }
