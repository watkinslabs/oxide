// `write_ldt` validation ladder.
//
// Two errnos and one strict order. The `bytecount` test comes FIRST, before
// the user pointer is touched at all, so `modify_ldt(1, garbage_ptr, 4)`
// reports EINVAL and never EFAULT — a caller probing the ABI's shape must not
// have that answer depend on whether its pointer happened to be mapped. Every
// later rule is EINVAL too; the only EFAULT in the whole sub-function is the
// copy the slot file performs between step 1 and step 2 below.

use syscall::errno::Errno;

use super::{desc, LdtFunc, UserDesc, ALLOW_16BIT_SEGMENTS, CONTENTS_RESERVED, LDT_ENTRIES,
            USER_DESC_BYTES};

/// The entry a validated write installs: which slot, and the 8 packed bytes
/// that go in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteEntry {
    pub entry_number: u32,
    pub desc: u64,
}

impl WriteEntry {
    /// Number of entries the table must hold to contain this one.
    /// # C: O(1)
    pub fn required_entries(&self) -> u32 { self.entry_number + 1 }
}

/// Step 1: the size test that precedes any dereference of the user pointer.
/// # C: O(1)
pub fn check_bytecount(bytecount: u64) -> Result<(), Errno> {
    if bytecount != USER_DESC_BYTES { return Err(Errno::Einval); }
    Ok(())
}

/// Step 2: every rule that can be decided from the decoded `user_desc`.
///
/// Returns the entry to install. Clearing an entry is not a separate outcome:
/// it is an all-zero descriptor written to the named slot, exactly as the
/// reference does it, so a cleared entry still extends the table and still
/// reads back as eight zero bytes.
/// # C: O(1)
pub fn validate_write(info: &UserDesc, func: LdtFunc) -> Result<WriteEntry, Errno> {
    let oldmode = func.oldmode();

    if info.entry_number >= LDT_ENTRIES { return Err(Errno::Einval); }

    // `contents == 3` encodes a conforming code segment. Conforming code
    // keeps the caller's CPL on a far transfer, so a PRESENT one is a way to
    // hold ring-0 privilege across a jump; only the not-present form is
    // accepted, and only through the newer sub-function, whose callers know
    // this rule exists.
    if info.contents == CONTENTS_RESERVED {
        if oldmode { return Err(Errno::Einval); }
        if !info.seg_not_present { return Err(Errno::Einval); }
    }

    // Clearing. Under the original semantics a zero base AND zero limit is
    // enough; otherwise the whole `user_desc` must match the empty shape.
    let clearing = (oldmode && info.base_addr == 0 && info.limit == 0)
        || desc::ldt_empty(info);

    let packed = if clearing {
        0
    } else {
        if !info.seg_32bit && !ALLOW_16BIT_SEGMENTS { return Err(Errno::Einval); }
        desc::fill_ldt(info, oldmode)
    };

    Ok(WriteEntry { entry_number: info.entry_number, desc: packed })
}
