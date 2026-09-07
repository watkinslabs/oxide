//! User boundary for the dynamic unwind function tables: registration,
//! removal, and the lookup leg the entry search consults after the loaded
//! images. The registry itself is process state owned by the thread group.

#![cfg(target_os = "oxide-kernel")]

use sched::nt_function_table as registry;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const FALSE: u64 = 0;
const TRUE: u64 = 1;

/// Route the dynamic unwind registration services.
/// # C: O(N_registrations) plus bounded user reads
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlAddFunctionTable => Some(add(call.args.a0, call.args.a1 as u32, call.args.a2)),
        NtService::RtlDeleteFunctionTable => Some(delete(call.args.a0)),
        NtService::RtlInstallFunctionTableCallback =>
            Some(install_callback(call.args.a0, call.args.a1, call.args.a2 as u32, call.args.a3, call.args.a4)),
        _ => None,
    }
}

fn entries_of(call: impl FnOnce(&mut alloc::vec::Vec<registry::Entry>) -> u64) -> u64 {
    let Some(cur) = sched::live::current() else { return FALSE; };
    if !cur.is_nt_personality() { return FALSE; }
    let mut entries = cur.thread_group.nt_function_tables.lock();
    call(&mut entries)
}

/// Read one entry's end address, which is where the covered code stops.
fn end_address(table: u64, index: u32) -> Option<u32> {
    let slot = table.checked_add(index as u64 * registry::ENTRY_BYTES)?
        .checked_add(registry::END_ADDRESS_OFFSET)?;
    uaccess::get_user_u32(slot).ok()
}

/// Register a static entry table. The registered range stops where the last
/// entry stops, so an unreadable last entry registers no code at all.
fn add(table: u64, count: u32, base: u64) -> u64 {
    let last = count.checked_sub(1).and_then(|index| end_address(table, index));
    let end = registry::static_range_end(base, count, last);
    entries_of(|entries| {
        if entries.try_reserve(1).is_err() { return STATUS_NO_MEMORY; }
        entries.push(registry::static_entry(table, count, base, end));
        TRUE
    })
}

fn delete(table: u64) -> u64 {
    entries_of(|entries| if registry::remove_by_table(entries, table) { TRUE } else { FALSE })
}

fn install_callback(table: u64, base: u64, length: u32, callback: u64, context: u64) -> u64 {
    let Some(entry) = registry::callback_entry(table, base, length, callback, context) else { return FALSE; };
    entries_of(|entries| {
        if entries.try_reserve(1).is_err() { return FALSE; }
        entries.push(entry);
        TRUE
    })
}

/// Resolve one program counter against the dynamic registrations, answering
/// the covering entry's address and the base it is relative to. A callback
/// registration supplies the entry itself, so the caller is the one that
/// enters it; nothing here calls user code.
/// # C: O(N_registrations + log N_entries)
pub fn lookup(pc: u64) -> Option<(u64, u64)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let found = { let entries = cur.thread_group.nt_function_tables.lock(); registry::lookup(&entries, pc)? };
    let (base, table, count) = match found {
        registry::Found::Table { base, table, count } => (base, table, count),
        // The producer's callback is user code; entering it is the caller's
        // business, so the registration reports the range it owns and stops.
        registry::Found::Callback { .. } => return None,
    };
    let offset = u32::try_from(pc.checked_sub(base)?).ok()?;
    let index = registry::find_entry(count, offset, |index| {
        let entry = table.checked_add(index as u64 * registry::ENTRY_BYTES)?;
        let begin = uaccess::get_user_u32(entry.checked_add(registry::BEGIN_ADDRESS_OFFSET)?).ok()?;
        let end = uaccess::get_user_u32(entry.checked_add(registry::END_ADDRESS_OFFSET)?).ok()?;
        Some((begin, end))
    })?;
    let mut entry = table.checked_add(index as u64 * registry::ENTRY_BYTES)?;
    // A chained entry defers to another, which is where the unwind data lives.
    for _ in 0..registry::CHAIN_DEPTH_LIMIT {
        let unwind = uaccess::get_user_u32(entry.checked_add(registry::UNWIND_DATA_OFFSET)?).ok()?;
        if unwind & registry::CHAINED_ENTRY == 0 { return Some((entry, base)); }
        entry = base.checked_add((unwind & !registry::CHAINED_ENTRY) as u64)?;
    }
    None
}
