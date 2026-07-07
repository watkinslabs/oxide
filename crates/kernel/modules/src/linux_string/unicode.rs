pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("utf16s_to_utf8s", utf16s_to_utf8s as *const () as usize),
        ("utf8s_to_utf16s", utf8s_to_utf16s as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) extern "C" fn utf16s_to_utf8s(src: *const u16, len: i32, endian: i32, dst: *mut u8, maxlen: i32) -> i32 {
    if src.is_null() || dst.is_null() || len <= 0 || maxlen <= 0 { return 0; }
    let mut out = 0usize;
    for i in 0..len as usize {
        let raw = unsafe { *src.add(i) };
        let ch = decode_u16(raw, endian) as u32;
        let Some(c) = char::from_u32(ch) else { continue; };
        let mut buf = [0u8; 4];
        let enc = c.encode_utf8(&mut buf).as_bytes();
        if out + enc.len() > maxlen as usize { break; }
        for b in enc {
            unsafe { *dst.add(out) = *b; }
            out += 1;
        }
    }
    out as i32
}

pub(crate) extern "C" fn utf8s_to_utf16s(src: *const u8, len: i32, endian: i32, dst: *mut u16, maxlen: i32) -> i32 {
    if src.is_null() || dst.is_null() || len <= 0 || maxlen <= 0 { return 0; }
    let bytes = unsafe { core::slice::from_raw_parts(src, len as usize) };
    let s = match core::str::from_utf8(bytes) { Ok(v) => v, Err(_) => return 0 };
    let mut out = 0usize;
    for c in s.chars() {
        let mut tmp = [0u16; 2];
        let enc = c.encode_utf16(&mut tmp);
        if out + enc.len() > maxlen as usize { break; }
        for w in enc {
            unsafe { *dst.add(out) = encode_u16(*w, endian); }
            out += 1;
        }
    }
    out as i32
}

fn decode_u16(v: u16, endian: i32) -> u16 {
    match endian {
        1 => u16::from_le(v),
        2 => u16::from_be(v),
        _ => v,
    }
}

fn encode_u16(v: u16, endian: i32) -> u16 {
    match endian {
        1 => v.to_le(),
        2 => v.to_be(),
        _ => v,
    }
}
