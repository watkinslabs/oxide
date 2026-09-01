//! Native lookup of exports from the kernel-provided ntdll runtime page.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_PROCEDURE_NOT_FOUND: u64 = 0xc000_007a;
const ANSI_STRING_BYTES: usize = 16;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_LDR_OFFSET: u64 = 0x18;
const LDR_LOAD_LIST_OFFSET: u64 = 0x10;
const MODULE_BASE_OFFSET: u64 = 0x30;
const LIST_LINK_OFFSET: u64 = 0;
const MAX_MODULE_SCAN: usize = 64;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::LdrGetProcedureAddress { return None; }
    Some(get_procedure(call))
}

fn get_procedure(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a3 == 0 { return STATUS_INVALID_PARAMETER; }
    if !module_loaded(&cur, call.args.a0) { return STATUS_INVALID_PARAMETER; }
    let Some(name) = read_ansi(call.args.a1) else {
        // Ordinal lookup is deliberately not accepted for the synthetic page:
        // the native catalog publishes named stubs only.
        if call.args.a1 != 0 { return STATUS_INVALID_PARAMETER; }
        return STATUS_PROCEDURE_NOT_FOUND;
    };
    let Some(address) = elf_load::pe_loader::resolve_nt_runtime_export(call.args.a0, &name) else {
        return STATUS_PROCEDURE_NOT_FOUND;
    };
    if uaccess::put_user_u64(call.args.a3, address).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn module_loaded(cur: &sched::Task, module: u64) -> bool {
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return false; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if read_u64(entry.saturating_add(MODULE_BASE_OFFSET)) == module { return true; }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    false
}

fn read_ansi(descriptor: u64) -> Option<Vec<u8>> {
    if descriptor == 0 { return None; }
    let mut raw = [0u8; ANSI_STRING_BYTES];
    uaccess::copy_from_user(&mut raw, descriptor).ok()?;
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length == 0 || length > maximum || length > 4096 || buffer == 0 { return None; }
    let mut value = Vec::new();
    value.resize(length, 0);
    uaccess::copy_from_user(&mut value, buffer).ok()?;
    Some(value)
}

fn read_u64(address: u64) -> u64 {
    let mut raw = [0u8; 8];
    if uaccess::copy_from_user(&mut raw, address).is_err() { 0 } else { u64::from_le_bytes(raw) }
}
