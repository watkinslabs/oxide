//! Process-local Windows atom service.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const FIRST_STRING_ATOM: u16 = 0xc000;
const MAX_ATOMS: usize = 0x4000;
const ATOM_TABLE_TOKEN: u64 = 1;

pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::AddAtom => Some(add(call.args.a0, call.args.a1 as usize, call.args.a2)),
        NtService::RtlCreateAtomTable => Some(create_table(call.args.a0 as u32, call.args.a1)),
        NtService::RtlDestroyAtomTable => Some(destroy_table(call.args.a0)),
        NtService::RtlDeleteAtomFromAtomTable => Some(rtl_delete(call.args.a0, call.args.a1 as u16)),
        NtService::RtlAddAtomToAtomTable => Some(rtl_add(call.args.a0, call.args.a1, call.args.a2)),
        NtService::DeleteAtom => Some(delete(call.args.a0 as u16)),
        NtService::FindAtom => Some(find(call.args.a0, call.args.a1 as usize, call.args.a2)),
        NtService::QueryInformationAtom => Some(query(call.args.a0 as u16, call.args.a1 as u32,
            call.args.a2, call.args.a3 as usize, call.args.a4)),
        _ => None,
    }
}

fn create_table(size: u32, output: u64) -> u64 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let existing = match uaccess::get_user_u64(output) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if existing != 0 { return if size == 0 { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }; }
    if uaccess::put_user_u64(output, ATOM_TABLE_TOKEN).is_err() { return STATUS_INVALID_PARAMETER; }
    *cur.thread_group.nt_atom_table.lock() = true;
    STATUS_SUCCESS
}

fn destroy_table(table: u64) -> u64 {
    if table != ATOM_TABLE_TOKEN { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut live = cur.thread_group.nt_atom_table.lock();
    if !*live { return STATUS_INVALID_PARAMETER; }
    cur.thread_group.nt_atoms.lock().clear();
    *live = false;
    STATUS_SUCCESS
}

fn rtl_delete(table: u64, atom: u16) -> u64 {
    if table == 0 { return STATUS_INVALID_PARAMETER; }
    if atom == 0 { return STATUS_INVALID_HANDLE; }
    if atom < FIRST_STRING_ATOM { return STATUS_SUCCESS; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let index = (atom - FIRST_STRING_ATOM) as usize;
    let mut atoms = cur.thread_group.nt_atoms.lock();
    if index >= atoms.len() || atoms[index].is_empty() { return STATUS_INVALID_HANDLE; }
    atoms[index].clear(); STATUS_SUCCESS
}

fn rtl_add(table: u64, name: u64, output: u64) -> u64 {
    if table == 0 || name == 0 || output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    if name <= u16::MAX as u64 {
        return if uaccess::copy_to_user(output, &(name as u16).to_le_bytes()).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER };
    }
    let mut value = Vec::new();
    for index in 0..255usize {
        let address = match name.checked_add((index * 2) as u64) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
        let mut pair = [0u8; 2];
        if uaccess::copy_from_user(&mut pair, address).is_err() { return STATUS_INVALID_PARAMETER; }
        if pair == [0, 0] { break; }
        value.extend_from_slice(&pair);
        if index == 254 { return STATUS_INVALID_PARAMETER; }
    }
    if value.is_empty() { return STATUS_INVALID_PARAMETER; }
    let mut atoms = cur.thread_group.nt_atoms.lock();
    if let Some(index) = atoms.iter().position(|entry| atom_name_eq(entry, &value)) {
        let atom = match FIRST_STRING_ATOM.checked_add(index as u16) { Some(value) => value, None => return STATUS_NO_MEMORY };
        return if uaccess::copy_to_user(output, &atom.to_le_bytes()).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER };
    }
    let index = if let Some(index) = atoms.iter().position(Vec::is_empty) { index } else {
        if atoms.len() >= MAX_ATOMS { return STATUS_NO_MEMORY; }
        atoms.len()
    };
    let atom = match FIRST_STRING_ATOM.checked_add(index as u16) { Some(value) => value, None => return STATUS_NO_MEMORY };
    if uaccess::copy_to_user(output, &atom.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if index == atoms.len() { atoms.push(value); } else { atoms[index] = value; }
    STATUS_SUCCESS
}

fn atom_name_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.chunks_exact(2).zip(right.chunks_exact(2)).all(|(a, b)| {
        let left = u16::from_le_bytes([a[0], a[1]]);
        let right = u16::from_le_bytes([b[0], b[1]]);
        left == right || left <= 0x7f && right <= 0x7f && fold_ascii(left) == fold_ascii(right)
    })
}

fn fold_ascii(value: u16) -> u16 { if value >= b'A' as u16 && value <= b'Z' as u16 { value + (b'a' - b'A') as u16 } else { value } }

fn add(name: u64, length: usize, output: u64) -> u64 {
    if name == 0 || output == 0 || length == 0 || length > 510 || length & 1 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut value = Vec::with_capacity(length);
    value.resize(length, 0);
    if uaccess::copy_from_user(&mut value, name).is_err() { return STATUS_INVALID_PARAMETER; }
    let mut atoms = cur.thread_group.nt_atoms.lock();
    let index = if let Some(index) = atoms.iter().position(|entry| *entry == value) {
        index
    } else {
        if let Some(index) = atoms.iter().position(Vec::is_empty) {
            atoms[index] = value;
            index
        } else {
            if atoms.len() >= MAX_ATOMS { return STATUS_NO_MEMORY; }
            atoms.push(value);
            atoms.len() - 1
        }
    };
    let Some(atom) = FIRST_STRING_ATOM.checked_add(index as u16) else { return STATUS_NO_MEMORY; };
    if uaccess::copy_to_user(output, &atom.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn delete(atom: u16) -> u64 {
    if atom == 0 { return STATUS_INVALID_HANDLE; }
    if atom < FIRST_STRING_ATOM { return STATUS_SUCCESS; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let index = (atom - FIRST_STRING_ATOM) as usize;
    let mut atoms = cur.thread_group.nt_atoms.lock();
    if index >= atoms.len() || atoms[index].is_empty() { return STATUS_INVALID_HANDLE; }
    atoms[index].clear();
    STATUS_SUCCESS
}

fn find(name: u64, length: usize, output: u64) -> u64 {
    if name == 0 || output == 0 || length == 0 || length > 510 || length & 1 != 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let mut value = Vec::with_capacity(length);
    value.resize(length, 0);
    if uaccess::copy_from_user(&mut value, name).is_err() { return STATUS_INVALID_PARAMETER; }
    let atoms = cur.thread_group.nt_atoms.lock();
    let Some(index) = atoms.iter().position(|entry| *entry == value) else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    let Some(atom) = FIRST_STRING_ATOM.checked_add(index as u16) else { return STATUS_OBJECT_NAME_NOT_FOUND; };
    if uaccess::copy_to_user(output, &atom.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn query(atom: u16, class: u32, info: u64, length: usize, return_length: u64) -> u64 {
    if class != 0 || info == 0 || length < 6 { return if class == 0 { STATUS_INVALID_PARAMETER } else { STATUS_INVALID_INFO_CLASS }; }
    if atom == 0 { return STATUS_INVALID_HANDLE; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let name = if atom < FIRST_STRING_ATOM {
        let mut digits = [0u8; 6];
        let mut value = atom as u32;
        let mut end = digits.len();
        while value != 0 { end -= 1; digits[end] = b'0' + (value % 10) as u8; value /= 10; }
        let mut bytes = Vec::with_capacity((digits.len() - end + 1) * 2);
        bytes.extend_from_slice(&(b'#' as u16).to_le_bytes());
        for byte in &digits[end..] { bytes.extend_from_slice(&(*byte as u16).to_le_bytes()); }
        bytes
    } else {
        let index = (atom - FIRST_STRING_ATOM) as usize;
        let atoms = cur.thread_group.nt_atoms.lock();
        let Some(value) = atoms.get(index).filter(|value| !value.is_empty()) else { return STATUS_INVALID_HANDLE; };
        value.clone()
    };
    let required = 6usize.saturating_add(name.len());
    if return_length != 0 && uaccess::put_user_u32(return_length, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 6];
    header[0..2].copy_from_slice(&1u16.to_le_bytes());
    header[2..4].copy_from_slice(&(if atom < FIRST_STRING_ATOM { 1u16 } else { 1u16 }).to_le_bytes());
    header[4..6].copy_from_slice(&(name.len() as u16).to_le_bytes());
    if uaccess::copy_to_user(info, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    let capacity = length - 6;
    if capacity < name.len() { return STATUS_BUFFER_TOO_SMALL; }
    if uaccess::copy_to_user(info + 6, &name).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
