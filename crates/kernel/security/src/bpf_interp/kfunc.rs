//! Interpreter runtime for kernel-BTF function calls.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::memory::RunMemory;
use crate::bpf::StreamKfunc;

const MAX_ARGS: usize = 12;
const MAX_TEXT: usize = 1024;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Dispatch one BTF-id call through its canonical program owner. # C: O(output)
pub(super) fn call(
    id: u32,
    memory: &RunMemory<'_>,
    stack: &[u8],
    regs: &[i64; super::NUM_REGS],
) -> Option<i64> {
    Some(match crate::bpf::stream_kfunc_by_btf_id(id)? {
        StreamKfunc::Vprintk => vprintk(memory, stack, regs),
    })
}

fn vprintk(memory: &RunMemory<'_>, stack: &[u8], regs: &[i64; super::NUM_REGS]) -> i64 {
    let Some(prog) = memory.prog() else { return err(Errno::Einval) };
    let Ok(stream_id) = u32::try_from(regs[1]) else { return err(Errno::Enoent) };
    let Ok(arg_len) = usize::try_from(regs[4]) else { return err(Errno::Einval) };
    if arg_len % 8 != 0 || arg_len > MAX_ARGS * 8 || arg_len != 0 && regs[3] == 0 {
        return err(Errno::Einval);
    }
    let Some(format) = c_string(memory, stack, regs[2]) else { return err(Errno::Einval) };
    let mut args = [0u64; MAX_ARGS];
    if arg_len != 0 {
        // SAFETY: the fixed array is initialized and u64 permits every byte pattern.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(args.as_mut_ptr().cast::<u8>(), arg_len)
        };
        if memory.read_bytes(regs[3], bytes, stack).is_none() { return err(Errno::Einval); }
    }
    let text = match render(memory, stack, &format, &args[..arg_len / 8]) {
        Some(text) => text,
        None => return err(Errno::Einval),
    };
    match prog.streams.push(stream_id, &text) { Ok(()) => 0, Err(e) => err(e) }
}

fn c_string(memory: &RunMemory<'_>, stack: &[u8], addr: i64) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    text.try_reserve(MAX_TEXT).ok()?;
    for offset in 0..MAX_TEXT {
        let mut byte = [0u8; 1];
        memory.read_bytes(addr.checked_add(offset as i64)?, &mut byte, stack)?;
        if byte[0] == 0 { return Some(text); }
        text.push(byte[0]);
    }
    None
}

fn render(
    memory: &RunMemory<'_>,
    stack: &[u8],
    format: &[u8],
    args: &[u64],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve(MAX_TEXT).ok()?;
    let mut at = 0usize;
    let mut arg = 0usize;
    while at < format.len() {
        let plain = format[at];
        if plain != b'%' {
            if plain.is_ascii_control() && !plain.is_ascii_whitespace() { return None; }
            append(&mut out, &[plain])?; at += 1; continue;
        }
        at += 1;
        if format.get(at) == Some(&b'%') { append(&mut out, b"%")?; at += 1; continue; }
        let mut flags = Flags::default();
        while let Some(flag) = format.get(at).copied() {
            match flag {
                b'0' => flags.zero = true, b'+' => flags.plus = true,
                b'-' => flags.left = true, b' ' => flags.space = true,
                _ => break,
            }
            at += 1;
        }
        let mut width = 0usize;
        while let Some(d @ b'1'..=b'9') = format.get(at).copied() {
            width = width.checked_mul(10)?.checked_add((d - b'0') as usize)?;
            at += 1;
            while let Some(d @ b'0'..=b'9') = format.get(at).copied() {
                width = width.checked_mul(10)?.checked_add((d - b'0') as usize)?;
                at += 1;
            }
        }
        let mut longs = 0usize;
        while format.get(at) == Some(&b'l') && longs < 2 { longs += 1; at += 1; }
        let spec = *format.get(at)?;
        at += 1;
        let value = *args.get(arg)?;
        arg += 1;
        match spec {
            b'd' | b'i' => integer(&mut out, value, true, 10, false, longs != 0, width, flags)?,
            b'u' => integer(&mut out, value, false, 10, false, longs != 0, width, flags)?,
            b'x' => integer(&mut out, value, false, 16, false, longs != 0, width, flags)?,
            b'X' => integer(&mut out, value, false, 16, true, longs != 0, width, flags)?,
            b'p' if longs == 0 => {
                let suffix = format.get(at).copied();
                match suffix {
                    Some(b'k' | b'u') if format.get(at + 1) == Some(&b's') => {
                        at += 2; field(&mut out, &c_string(memory, stack, value as i64)?, width, flags)?;
                    }
                    Some(b'i' | b'I') if matches!(format.get(at + 1), Some(b'4' | b'6')) => {
                        let kind = suffix.unwrap();
                        let size = if format[at + 1] == b'4' { 4 } else { 16 };
                        at += 2;
                        let mut address = [0u8; 16];
                        memory.read_bytes(value as i64, &mut address[..size], stack)?;
                        let text = ip_text(&address[..size], kind == b'I')?;
                        field(&mut out, &text, width, flags)?;
                    }
                    Some(b'K' | b'x' | b's' | b'S' | b'B') => {
                        at += 1;
                        integer(&mut out, value, false, 16, false, true, width, flags)?;
                    }
                    None | Some(b' '..=b'/') | Some(b':'..=b'@') | Some(b'['..=b'`')
                        | Some(b'{'..=b'~') => {
                        integer(&mut out, value, false, 16, false, true, width, flags)?;
                    }
                    _ => return None,
                }
            }
            b'c' if longs == 0 => field(&mut out, &[value as u8], width, flags)?,
            b's' => {
                if longs != 0 { return None; }
                let string = c_string(memory, stack, value as i64)?;
                field(&mut out, &string, width, flags)?;
            }
            _ => return None,
        }
    }
    Some(out)
}

#[derive(Copy, Clone, Default)]
struct Flags { zero: bool, plus: bool, left: bool, space: bool }

fn integer(
    out: &mut Vec<u8>, raw: u64, signed: bool, radix: u64, upper: bool,
    wide: bool, width: usize, flags: Flags,
) -> Option<()> {
    let raw = if wide { raw } else { raw as u32 as u64 };
    let signed_value = if wide { raw as i64 } else { raw as u32 as i32 as i64 };
    let negative = signed && signed_value < 0;
    let mut value = if negative { signed_value.unsigned_abs() } else { raw };
    let mut digits = [0u8; 64];
    let mut used = 0usize;
    loop {
        let digit = (value % radix) as u8;
        digits[used] = if digit < 10 { b'0' + digit }
            else { (if upper { b'A' } else { b'a' }) + digit - 10 };
        used += 1;
        value /= radix;
        if value == 0 { break; }
    }
    let sign = if negative { Some(b'-') }
        else if signed && flags.plus { Some(b'+') }
        else if signed && flags.space { Some(b' ') } else { None };
    let total = used + usize::from(sign.is_some());
    let pad = width.saturating_sub(total);
    if !flags.left && !flags.zero { for _ in 0..pad { append(out, b" ")?; } }
    if let Some(sign) = sign { append(out, &[sign])?; }
    if !flags.left && flags.zero { for _ in 0..pad { append(out, b"0")?; } }
    while used != 0 { used -= 1; append(out, &digits[used..used + 1])?; }
    if flags.left { for _ in 0..pad { append(out, b" ")?; } }
    Some(())
}

fn field(out: &mut Vec<u8>, bytes: &[u8], width: usize, flags: Flags) -> Option<()> {
    let pad = width.saturating_sub(bytes.len());
    if !flags.left { for _ in 0..pad { append(out, b" ")?; } }
    append(out, bytes)?;
    if flags.left { for _ in 0..pad { append(out, b" ")?; } }
    Some(())
}

fn ip_text(address: &[u8], separated: bool) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve(48).ok()?;
    if address.len() == 4 {
        for (at, byte) in address.iter().enumerate() {
            if at != 0 { append(&mut out, b".")?; }
            integer(&mut out, *byte as u64, false, 10, false, false, 0, Flags::default())?;
        }
    } else {
        for at in 0..8 {
            if separated && at != 0 { append(&mut out, b":")?; }
            let word = u16::from_be_bytes([address[at * 2], address[at * 2 + 1]]);
            integer(&mut out, word as u64, false, 16, false, false,
                if separated { 0 } else { 4 }, Flags { zero: true, ..Flags::default() })?;
        }
    }
    Some(out)
}

fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    if out.len().checked_add(bytes.len())? >= MAX_TEXT { return None; }
    out.extend_from_slice(bytes);
    Some(())
}
