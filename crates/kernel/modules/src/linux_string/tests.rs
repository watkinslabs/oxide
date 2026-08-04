use super::{bitops, cstr, format, match_parser, mem, parse, unicode};
use core::ffi::c_void;

#[test]
fn mem_and_cstr_helpers_match_c_contracts() {
    let _modules = crate::test_serial::claim();
    let mut buf = [0u8; 8];
    unsafe { mem::memset(buf.as_mut_ptr() as *mut c_void, b'a' as i32, 3); }
    assert_eq!(&buf[..4], b"aaa\0");
    unsafe { cstr::strcpy(buf.as_mut_ptr(), b"AbC\0".as_ptr()); }
    assert_eq!(unsafe { cstr::strlen(buf.as_ptr()) }, 3);
    assert_eq!(unsafe { cstr::strncasecmp(buf.as_ptr(), b"abc\0".as_ptr(), 3) }, 0);
    assert!(!unsafe { cstr::strchr(buf.as_ptr(), b'b' as i32) }.is_null());
}

#[test]
fn parse_helpers_convert_linux_numbers() {
    let _modules = crate::test_serial::claim();
    let mut v8 = 0u8;
    let mut v16 = 0u16;
    let mut vi = 0i32;
    let mut b = false;
    assert_eq!(unsafe { parse::kstrtou8(b"0xff\n\0".as_ptr(), 0, &mut v8) }, 0);
    assert_eq!(v8, 255);
    assert_eq!(unsafe { parse::kstrtou16(b"0777\0".as_ptr(), 0, &mut v16) }, 0);
    assert_eq!(v16, 0o777);
    assert_eq!(unsafe { parse::kstrtoint(b"-42\0".as_ptr(), 10, &mut vi) }, 0);
    assert_eq!(vi, -42);
    assert_eq!(unsafe { parse::kstrtobool(b"on\n\0".as_ptr(), &mut b) }, 0);
    assert!(b);
}

#[test]
fn scanf_match_bit_and_unicode_helpers_cover_runtime_utility_surface() {
    let _modules = crate::test_serial::claim();
    let mut iv = 0i32;
    let mut word = [0u8; 8];
    assert_eq!(unsafe { parse::sscanf(b"17 fast\0".as_ptr(), b"%d %s\0".as_ptr(), &mut iv, word.as_mut_ptr()) }, 2);
    assert_eq!(iv, 17);
    assert_eq!(&word[..5], b"fast\0");

    let bits = [0b1000_0000usize, 0];
    assert_eq!(bitops::_find_first_bit(bits.as_ptr(), usize::BITS as usize * 2), 7);
    assert_eq!(bitops::_find_next_bit(bits.as_ptr(), usize::BITS as usize * 2, 8), usize::BITS as usize * 2);

    let mut wide = [0u16; 4];
    let mut narrow = [0u8; 8];
    assert_eq!(unicode::utf8s_to_utf16s(b"ok".as_ptr(), 2, 0, wide.as_mut_ptr(), wide.len() as i32), 2);
    assert_eq!(unicode::utf16s_to_utf8s(wide.as_ptr(), 2, 0, narrow.as_mut_ptr(), narrow.len() as i32), 2);
    assert_eq!(&narrow[..2], b"ok");

    let table = [
        match_parser::MatchToken { token: 3, pattern: b"mode=%s\0".as_ptr() },
        match_parser::MatchToken { token: 0, pattern: core::ptr::null() },
    ];
    let mut args = [match_parser::Substring { from: core::ptr::null(), to: core::ptr::null() }];
    assert_eq!(unsafe { match_parser::match_token(b"mode=42\0".as_ptr(), table.as_ptr(), args.as_mut_ptr()) }, 3);
    let mut mv = 0i32;
    assert_eq!(unsafe { match_parser::match_int(args.as_ptr(), &mut mv) }, 0);
    assert_eq!(mv, 42);

    let table = [
        match_parser::MatchToken { token: 4, pattern: b"rate=100%%\0".as_ptr() },
        match_parser::MatchToken { token: 5, pattern: b"name=%3s!\0".as_ptr() },
        match_parser::MatchToken { token: 6, pattern: b"mask=%x\0".as_ptr() },
        match_parser::MatchToken { token: 0, pattern: core::ptr::null() },
    ];
    let mut args = [
        match_parser::Substring { from: core::ptr::null(), to: core::ptr::null() },
        match_parser::Substring { from: core::ptr::null(), to: core::ptr::null() },
        match_parser::Substring { from: core::ptr::null(), to: core::ptr::null() },
    ];
    assert_eq!(unsafe { match_parser::match_token(b"rate=100%\0".as_ptr(), table.as_ptr(), args.as_mut_ptr()) }, 4);
    assert_eq!(unsafe { match_parser::match_token(b"name=abc!\0".as_ptr(), table.as_ptr(), args.as_mut_ptr()) }, 5);
    assert_eq!(unsafe { args[0].to.offset_from(args[0].from) }, 3);
    assert_eq!(unsafe { match_parser::match_token(b"mask=0x2a\0".as_ptr(), table.as_ptr(), args.as_mut_ptr()) }, 6);
    assert_eq!(unsafe { args[0].to.offset_from(args[0].from) }, 4);
}

#[test]
fn hex_helpers_round_trip_bytes() {
    let _modules = crate::test_serial::claim();
    let mut bin = [0u8; 2];
    let mut hex = [0u8; 4];
    assert_eq!(unsafe { parse::hex2bin(bin.as_mut_ptr(), b"0aff".as_ptr(), 2) }, 0);
    assert_eq!(bin, [0x0a, 0xff]);
    unsafe { parse::bin2hex(hex.as_mut_ptr(), bin.as_ptr(), 2); }
    assert_eq!(&hex, b"0aff");
}

#[test]
fn format_exports_write_bounded_output() {
    let _modules = crate::test_serial::claim();
    let mut out = [0u8; 8];
    let n = unsafe { format::snprintf(out.as_mut_ptr(), out.len(), b"%s-%d\0".as_ptr(), b"irq\0".as_ptr(), -7i32) };
    assert_eq!(n, 6);
    assert_eq!(&out[..7], b"irq--7\0");
}

#[test]
fn export_symbols_registers_string_surface() {
    let _modules = crate::test_serial::claim();
    crate::linux_string::export_symbols();
    for name in [
        "memcpy", "memset", "memcmp", "strlen", "strcmp", "strncasecmp",
        "kstrtou8", "kstrtou16", "kstrtoint", "hex_to_bin", "hex2bin", "bin2hex",
        "snprintf", "scnprintf", "sprintf", "_printk", "__stack_chk_fail",
        "__dynamic_pr_debug", "_ctype", "__ref_stack_chk_guard", "sscanf",
        "_find_first_bit", "_find_next_bit", "match_token", "match_int",
        "utf16s_to_utf8s", "utf8s_to_utf16s", "print_hex_dump",
    ] {
        assert!(crate::symtab::is_exported(name), "{name}");
    }
}
