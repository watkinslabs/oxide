// The table type and its scan are reached from `lookup` (kernel target only)
// and from the host unit test at the bottom of this file.
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
#[repr(C)]
struct Entry {
    insn: i32,
    fixup: i32,
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    static __ex_table_start: Entry;
    static __ex_table_end: Entry;
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn lookup_range(start: *const Entry, end: *const Entry, pc: u64) -> Option<u64> {
    let bytes = (end as usize).checked_sub(start as usize)?;
    if bytes % core::mem::size_of::<Entry>() != 0 { return None; }
    let count = bytes / core::mem::size_of::<Entry>();
    for i in 0..count {
        // SAFETY: caller-provided bounds contain `count` complete entries.
        let entry = unsafe { &*start.add(i) };
        let insn = core::ptr::addr_of!(entry.insn) as u64;
        if insn.wrapping_add_signed(entry.insn as i64) == pc {
            let fixup = core::ptr::addr_of!(entry.fixup) as u64;
            return Some(fixup.wrapping_add_signed(entry.fixup as i64));
        }
    }
    None
}

/// Find the fixup for one faulting kernel instruction. # C: O(entries)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub(crate) fn lookup(pc: u64) -> Option<u64> {
    lookup_range(core::ptr::addr_of!(__ex_table_start), core::ptr::addr_of!(__ex_table_end), pc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_lookup_finds_first_and_last_only() {
        let mut entries = [Entry { insn: 0, fixup: 0 }, Entry { insn: 0, fixup: 0 }];
        let mut pcs = [0u64; 2];
        let mut fixes = [0u64; 2];
        for i in 0..entries.len() {
            let insn_at = core::ptr::addr_of!(entries[i].insn) as u64;
            let fixup_at = core::ptr::addr_of!(entries[i].fixup) as u64;
            pcs[i] = insn_at + 0x100 + i as u64;
            fixes[i] = fixup_at + 0x200 + i as u64;
            entries[i].insn = pcs[i].wrapping_sub(insn_at) as i32;
            entries[i].fixup = fixes[i].wrapping_sub(fixup_at) as i32;
        }
        let start = entries.as_ptr();
        // SAFETY: one-past-end pointer of the local entry array.
        let end = unsafe { start.add(entries.len()) };
        assert_eq!(lookup_range(start, end, pcs[0]), Some(fixes[0]));
        assert_eq!(lookup_range(start, end, pcs[1]), Some(fixes[1]));
        assert_eq!(lookup_range(start, end, pcs[1] + 4), None);
    }
}
