// /etc/shells database (docs/59§6 §9.1) — getusershell/setusershell/endusershell.
// glibc exposes a non-reentrant process-global cursor; callers use
// setusershell to rewind and endusershell to discard cached entries.
#![cfg(feature = "freestanding")]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

const BUF: usize = 4096;

struct State {
    entries: Vec<String>,
    idx: usize,
    loaded: bool,
    buf: [u8; BUF],
}

struct Cell(UnsafeCell<State>);
// SAFETY: getusershell follows glibc's process-global, non-thread-safe
// enumeration contract; this state is intentionally shared by those calls.
unsafe impl Sync for Cell {}

static S: Cell = Cell(UnsafeCell::new(State {
    entries: Vec::new(),
    idx: 0,
    loaded: false,
    buf: [0; BUF],
}));

fn parse_line(line: &str) -> Option<String> {
    let s = line.trim_start_matches([' ', '\t']);
    if s.is_empty() || s.starts_with('#') { return None; }
    let end = s.find([' ', '\t', '#']).unwrap_or(s.len());
    let shell = &s[..end];
    if shell.starts_with('/') { Some(String::from(shell)) } else { None }
}

unsafe fn load(state: &mut State) {
    // SAFETY: read_file returns owned bytes for /etc/shells; parsing stores
    // owned Strings so returned pointers remain tied to State::buf only.
    unsafe {
        state.entries.clear();
        state.idx = 0;
        if let Some(b) = crate::nss::shared::read_file(b"/etc/shells\0") {
            state.entries = core::str::from_utf8(&b)
                .unwrap_or("")
                .lines()
                .filter_map(parse_line)
                .collect();
        }
        if state.entries.is_empty() {
            state.entries.push(String::from("/bin/sh"));
            state.entries.push(String::from("/bin/csh"));
        }
        state.loaded = true;
    }
}

// # C: char *getusershell(void)
#[no_mangle]
pub unsafe extern "C" fn getusershell() -> *mut u8 {
    // SAFETY: returns a pointer into the process-global static buffer, matching
    // glibc's non-reentrant usershell enumeration contract.
    unsafe {
        let s = &mut *S.0.get();
        if !s.loaded { load(s); }
        while s.idx < s.entries.len() {
            let ent = s.entries[s.idx].as_bytes();
            s.idx += 1;
            if ent.len() + 1 > s.buf.len() { continue; }
            core::ptr::copy_nonoverlapping(ent.as_ptr(), s.buf.as_mut_ptr(), ent.len());
            s.buf[ent.len()] = 0;
            return s.buf.as_mut_ptr();
        }
        core::ptr::null_mut()
    }
}

// # C: void setusershell(void)
#[no_mangle]
pub unsafe extern "C" fn setusershell() {
    // SAFETY: rewind by forcing a fresh /etc/shells read into the global state.
    unsafe {
        let s = &mut *S.0.get();
        s.loaded = false;
        load(s);
    }
}

// # C: void endusershell(void)
#[no_mangle]
pub unsafe extern "C" fn endusershell() {
    // SAFETY: discard the single process-global usershell cache and cursor.
    unsafe {
        let s = &mut *S.0.get();
        s.entries = Vec::new();
        s.idx = 0;
        s.loaded = false;
    }
}
