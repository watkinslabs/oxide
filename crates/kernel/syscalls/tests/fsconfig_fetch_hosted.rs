// fsconfig(2) 431 — the user-memory copy-in stage: which read happens, in what
// ORDER, and what a failed read reports.
//
// Every EFAULT rung of this syscall used to live in `431_fsconfig.rs`, which is
// `#![cfg(target_os = "oxide-kernel")]` — untestable, because a `#[cfg(test)]`
// block there compiles out silently. The reads now sit behind
// `fsconfig_fetch::UserCopy`, so a fake address space can fault any one of them
// and the assertion goes RED when the ordering changes.

use alloc::vec::Vec;
extern crate alloc;

use syscall::errno::Errno;
use syscalls::fsconfig_abi::{self as abi, FsconfigCmd, KEY_MAX, VALUE_MAX};
use syscalls::fsconfig_fetch::{fetch, Fetched, UserCopy};

/// A fake user address space: a pointer is readable only if it was placed here.
/// Everything else faults, which is what makes the EFAULT rungs reachable.
#[derive(Default)]
struct Mem(alloc::collections::BTreeMap<u64, Vec<u8>>);

impl Mem {
    fn at(mut self, ptr: u64, bytes: &[u8]) -> Self {
        self.0.insert(ptr, bytes.to_vec());
        self
    }
}

impl UserCopy for Mem {
    fn cstr(&self, ptr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        let b = self.0.get(&ptr).ok_or(Errno::Efault)?;
        // Stop at the first NUL or at `max`, whichever comes first — never a
        // terminator in the result.
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len()).min(max);
        Ok(b[..end].to_vec())
    }
    fn bytes(&self, ptr: u64, len: usize) -> Result<Vec<u8>, Errno> {
        let b = self.0.get(&ptr).ok_or(Errno::Efault)?;
        if b.len() < len { return Err(Errno::Efault); }
        Ok(b[..len].to_vec())
    }
}

const KEY: u64 = 0x1000;
const VAL: u64 = 0x2000;
const BAD: u64 = 0xdead_0000;

fn mem() -> Mem { Mem::default().at(KEY, b"fd\0").at(VAL, b"ro\0") }

#[test]
fn a_string_command_copies_both_halves() {
    let f = fetch(FsconfigCmd::SetString, KEY, VAL, 0, &mem()).unwrap();
    assert_eq!(f, Fetched { key: "fd".into(), value: "ro".into(), blob: None });
}

#[test]
fn a_flag_command_reads_the_key_and_no_value() {
    // The value pointer is unreadable and must never be touched.
    let f = fetch(FsconfigCmd::SetFlag, KEY, BAD, 0, &mem()).unwrap();
    assert_eq!(f.key, "fd");
    assert!(f.value.is_empty() && f.blob.is_none());
}

// The CMD_* trio carries neither, so a call with both pointers unreadable still
// succeeds — a fetch that read them unconditionally would turn every
// `fsconfig(FSCONFIG_CMD_CREATE)` into EFAULT.
#[test]
fn the_command_trio_reads_no_user_memory_at_all() {
    for c in [FsconfigCmd::CmdCreate, FsconfigCmd::CmdCreateExcl, FsconfigCmd::CmdReconfigure] {
        assert_eq!(fetch(c, BAD, BAD, 0, &Mem::default()).unwrap(), Fetched::default());
    }
}

// ORDER is observable. With both pointers bad the caller sees the KEY's
// failure; a fetch that read the value first would report the same errno for a
// different reason, and a fetch that read the value first for SET_BINARY would
// allocate a megabyte before noticing the key was garbage.
#[test]
fn the_key_is_read_before_the_value() {
    assert_eq!(fetch(FsconfigCmd::SetString, BAD, BAD, 0, &mem()).unwrap_err(), Errno::Efault);
    // Proving it is the KEY that failed: make the key good and the value bad —
    // still EFAULT; make the key bad and the value good — still EFAULT. The
    // discriminating case is an over-long KEY with a bad value pointer, which
    // must report the key's EINVAL and never reach the value at all.
    let long = alloc::vec![b'k'; KEY_MAX + 8];
    let m = Mem::default().at(KEY, &long);
    assert_eq!(fetch(FsconfigCmd::SetString, KEY, BAD, 0, &m).unwrap_err(), Errno::Einval);
}

// `strndup_user`: a string that does not terminate inside the bound is EINVAL,
// NOT a silent prefix — a truncated option name is a DIFFERENT option, and one
// the filesystem may well accept.
#[test]
fn an_unterminated_key_or_value_is_einval_not_a_prefix() {
    let long_key = alloc::vec![b'k'; KEY_MAX + 1];
    let m = Mem::default().at(KEY, &long_key).at(VAL, b"ro\0");
    assert_eq!(fetch(FsconfigCmd::SetString, KEY, VAL, 0, &m).unwrap_err(), Errno::Einval);

    let long_val = alloc::vec![b'v'; VALUE_MAX + 1];
    let m = Mem::default().at(KEY, b"errors\0").at(VAL, &long_val);
    assert_eq!(fetch(FsconfigCmd::SetString, KEY, VAL, 0, &m).unwrap_err(), Errno::Einval);

    // The longest key that DOES terminate inside the bound is accepted whole.
    let fits = alloc::vec![b'k'; KEY_MAX - 1];
    let mut term = fits.clone();
    term.push(0);
    let m = Mem::default().at(KEY, &term).at(VAL, b"1\0");
    assert_eq!(fetch(FsconfigCmd::SetString, KEY, VAL, 0, &m).unwrap().key.len(), KEY_MAX - 1);
}

// A pathname is not required to be UTF-8: path bytes are opaque, and a
// `journal_path=` naming a non-UTF-8 file must reach the filesystem unchanged
// rather than becoming EINVAL in the syscall.
#[test]
fn a_path_value_survives_non_utf8_bytes_where_a_string_value_would_not() {
    let m = Mem::default().at(KEY, b"journal_path\0").at(VAL, b"/\xff\xfe/j\0");
    let f = fetch(FsconfigCmd::SetPath, KEY, VAL, -100, &m).unwrap();
    assert!(!f.value.is_empty(), "the pathname is carried, not rejected");
    assert_eq!(fetch(FsconfigCmd::SetString, KEY, VAL, 0, &m).unwrap_err(), Errno::Einval);
}

// An EFAULT beats the empty-path ENOENT: the pointer is dereferenced before its
// contents can be judged.
#[test]
fn an_unreadable_path_pointer_is_efault_and_a_readable_empty_one_is_enoent() {
    let m = Mem::default().at(KEY, b"journal_path\0").at(VAL, b"\0");
    assert_eq!(fetch(FsconfigCmd::SetPath, KEY, BAD, -100, &m).unwrap_err(), Errno::Efault);
    assert_eq!(fetch(FsconfigCmd::SetPath, KEY, VAL, -100, &m).unwrap_err(), Errno::Enoent);
    // Only the _EMPTY variant admits it.
    assert_eq!(fetch(FsconfigCmd::SetPathEmpty, KEY, VAL, -100, &m).unwrap().value, "");
}

#[test]
fn an_over_long_path_is_enametoolong() {
    let long = alloc::vec![b'p'; vfs::path::PATH_MAX + 1];
    let m = Mem::default().at(KEY, b"journal_path\0").at(VAL, &long);
    assert_eq!(fetch(FsconfigCmd::SetPath, KEY, VAL, -100, &m).unwrap_err(),
        Errno::Enametoolong);
}

// The blob is `aux` bytes exactly, NUL included — it is not a C string, so a
// zero byte inside it must not shorten it.
#[test]
fn a_binary_value_copies_aux_bytes_including_embedded_nuls() {
    let m = Mem::default().at(KEY, b"blob\0").at(VAL, b"\x01\x00\x02\x03");
    let f = fetch(FsconfigCmd::SetBinary, KEY, VAL, 4, &m).unwrap();
    assert_eq!(f.blob.as_deref(), Some(&b"\x01\x00\x02\x03"[..]));
    assert!(f.value.is_empty());
    assert_eq!(fetch(FsconfigCmd::SetBinary, KEY, BAD, 4, &m).unwrap_err(), Errno::Efault);
}

// SET_FD names its file by the `aux` descriptor, so it reads a key and NO
// value; a fetch that read `_value` here would fault on the NULL the admission
// switch requires.
#[test]
fn set_fd_reads_a_key_and_never_touches_the_value_pointer() {
    assert_eq!(abi::classify(3, abi::FSCONFIG_SET_FD, KEY, 0, 7), Ok(FsconfigCmd::SetFd));
    let f = fetch(FsconfigCmd::SetFd, KEY, 0, 7, &mem()).unwrap();
    assert_eq!(f.key, "fd");
    assert!(f.value.is_empty() && f.blob.is_none());
}

// The two stages compose in the reference's order: argument admission settles
// which pointers are even legal BEFORE any of them is dereferenced, so a
// command whose `_value` must be NULL never reaches a copy-in.
#[test]
fn admission_runs_before_any_user_memory_is_touched() {
    // `SET_FLAG` with a non-NULL value is EINVAL from the switch, not EFAULT
    // from a read of that pointer.
    assert_eq!(abi::classify(3, abi::FSCONFIG_SET_FLAG, KEY, BAD, 0), Err(Errno::Einval));
    // And a negative context fd is EINVAL before the command is even looked at.
    assert_eq!(abi::classify(-1, abi::FSCONFIG_SET_STRING, BAD, BAD, 0), Err(Errno::Einval));
}
